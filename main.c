#include <linux/file.h>
#include <linux/time.h>
#include <linux/ftrace.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/pagemap.h>
#include <linux/spinlock.h>
#include <linux/kallsyms.h>
#include <linux/kvm_host.h>

#include "utils.h"
#define SEARCH_BYTES "Daniel"

static typeof(kvm_arch_vcpu_ioctl_get_sregs) *get_sregs;
static typeof(kvm_arch_vcpu_ioctl_get_regs) *get_regs;
static unsigned long original_vcpu_ioctl = 0;

static void vcpu_ioctl_handler(struct file *filp, unsigned int ioctl, unsigned long arg)
{
    int res;
    static bool done_searching = false;
    static DEFINE_SPINLOCK(lock);

    spin_lock(&lock);

    if (done_searching) {
        goto cleanup;
    }

    if (KVM_RUN == ioctl) {
        struct kvm_vcpu *vcpu = filp->private_data;
        CHECK(vcpu, "vcpu is NULL");
        struct kvm *kvm = vcpu->kvm;
        CHECK(kvm, "vcpu->kvm is NULL");

		struct kvm_sregs *sregs = kzalloc(sizeof(struct kvm_sregs), GFP_KERNEL);
        CHECK(sregs, "failed to allocate sregs");

        res = get_sregs(vcpu, sregs);
        CHECK_OR(!res, free_sregs, "kvm_arch_vcpu_ioctl_get_sregs failed with %d", res);
        CHECK_OR(0 == (sregs->cs.base & 3), free_sregs, "guest is not in kernel mode");

        struct kvm_memslots *memslots = kvm->memslots[0];
        CHECK_OR(memslots, free_sregs, "memslots is NULL");

        println("searching for '" SEARCH_BYTES "' in the VM's entire memory space");
        struct timespec scan_time;
        getnstimeofday(&scan_time);

        gpa_t addr = 0;
        unsigned pages_scanned = 0;
        struct kvm_memory_slot *memslot;
        kvm_for_each_memslot(memslot, memslots) {
            println("scanning memslot: userspace address=%lx, pages=%ld, guest page=%llu",
                    memslot->userspace_addr, memslot->npages, memslot->base_gfn);

            void *_addr = NULL;
            int pages_pinned = 0;
            void *scan_pages = NULL;

		    struct page **user_pages = kzalloc(sizeof(void *) * memslot->npages, GFP_KERNEL);
            CHECK_OR(user_pages, next_memslot, "failed to allocate pages pointers");

            pages_pinned = __get_user_pages_fast(memslot->userspace_addr, memslot->npages, 0, user_pages);
            CHECK_OR(pages_pinned == memslot->npages, next_memslot,
                    "failed to pin %ld pages starting from 0x%lx, skipping", memslot->npages, memslot->userspace_addr);

            scan_pages = vmap(user_pages, memslot->npages, GFP_KERNEL, PAGE_KERNEL);
            CHECK_OR(scan_pages, next_memslot,
                    "failed to map %ld pages starting from 0x%lx, skipping", memslot->npages, memslot->userspace_addr);

            _addr = memmem(scan_pages, PAGE_SIZE * memslot->npages, SEARCH_BYTES, sizeof(SEARCH_BYTES) - 1);
            pages_scanned += memslot->npages;

next_memslot:
            if (scan_pages) {
                vunmap(scan_pages);
            }
            if (pages_pinned > 0) {
                release_pages(user_pages, memslot->npages);
            }
            if (user_pages) {
                kfree(user_pages);
            }

            if (_addr) {
                addr = memslot->userspace_addr + (_addr - scan_pages);
                break;
            }
        }

        struct timespec now;
        getnstimeofday(&now);
        println("finished scanning %u pages in %ld.%09ld seconds",
                pages_scanned,
                now.tv_sec - scan_time.tv_sec,
                (1000000000 + now.tv_nsec - scan_time.tv_nsec) % 1000000000);

        if (addr) {
            println("found string at location 0x%llx", addr);
        } else {
            println("couldn't find string :(");
        }

        done_searching = true;

        static char* rmmod_args[] = {"/bin/sh", "-c", "rmmod " MODULE_NAME ".ko", NULL};
        static char* rmmod_envp[] = {"HOME=/tmp", NULL};
        call_usermodehelper(rmmod_args[0], rmmod_args, rmmod_envp, UMH_NO_WAIT);

free_sregs:
        kfree(sregs);
    }

cleanup:
    spin_unlock(&lock);
}

static void __vcpu_ioctl_handler(unsigned long ip, unsigned long parent_ip,
                   struct ftrace_ops *op, struct pt_regs *regs)
{
    if (ip != original_vcpu_ioctl) {
        eprintln("ftrace handler called from a different function (0x%lx)!!", ip);
        return;
    }

    vcpu_ioctl_handler((void *)regs->di, regs->si, regs->dx);
}

static struct ftrace_ops ops = {
    .func = __vcpu_ioctl_handler,
    .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RCU,
};

static int __init init_mod(void)
{
    int res = 0;

    get_sregs = (void *)kallsyms_lookup_name("kvm_arch_vcpu_ioctl_get_sregs");
    CHECK(get_sregs, "failed to find kvm_arch_vcpu_ioctl_get_sregs");
    get_regs = (void *)kallsyms_lookup_name("kvm_arch_vcpu_ioctl_get_regs");
    CHECK(get_regs, "failed to find kvm_arch_vcpu_ioctl_get_regs");

    original_vcpu_ioctl = kallsyms_lookup_name("kvm_vcpu_ioctl");
    CHECK(original_vcpu_ioctl, "failed to find kvm_vcpu_ioctl");
    res = ftrace_set_filter(&ops, "kvm_vcpu_ioctl", sizeof("kvm_vcpu_ioctl") - 1, true);
    CHECK(!res, "failed to set ftrace filter with error %d", res);
    res = register_ftrace_function(&ops);
    CHECK(!res, "failed to register ftrace function with error %d", res);

    println("loaded!");

cleanup:
    return res;
}

static void __exit exit_mod(void)
{
    unregister_ftrace_function(&ops);
    printk("exited!\n");
}

module_init(init_mod);
module_exit(exit_mod);
MODULE_LICENSE("GPL");
