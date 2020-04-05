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

gpa_t map_and_search_pages(gpa_t userspace_addr, unsigned long npages, unsigned long *scanned_count)
{
    gpa_t res = 0;
    int pages_pinned = 0;
    void *scan_pages = NULL;

    struct page **user_pages = kzalloc(sizeof(void *) * npages, GFP_KERNEL);
    CHECK(user_pages, "failed to allocate pages pointers");

    pages_pinned = get_user_pages_fast(userspace_addr, npages, 0, user_pages);
    CHECK(pages_pinned == npages, "failed to pin %ld pages starting from 0x%llx, skipping", npages, userspace_addr);

    scan_pages = vmap(user_pages, npages, GFP_KERNEL, PAGE_KERNEL);
    CHECK(scan_pages, "failed to map %ld pages starting from 0x%llx, skipping", npages, userspace_addr);

    res = (gpa_t)memmem(scan_pages, PAGE_SIZE * npages, SEARCH_BYTES, sizeof(SEARCH_BYTES) - 1);
    if (res) {
        res = userspace_addr + (gpa_t)(scan_pages - res);
    }

    *scanned_count += npages;

cleanup:
    if (scan_pages) {
        vunmap(scan_pages);
    }
    if (pages_pinned > 0) {
        release_pages(user_pages, npages);
    }
    if (user_pages) {
        kfree(user_pages);
    }

    return res;
}

gpa_t read_and_search_pages(gpa_t userspace_addr, unsigned long npages, unsigned long *scanned_count)
{
    gpa_t res = 0;

    void *scan_buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    CHECK(scan_buffer, "failed to allocate scanning buffer");

    for (unsigned long i = 0; i < npages; i++) {
        void *__user current_page = (void *__user)userspace_addr + i * PAGE_SIZE;
        int err = __copy_from_user(scan_buffer, current_page, PAGE_SIZE);
        if (err) {
            eprintln("failed to read page from userspace address %llx. skipping", (unsigned long long)current_page);
            continue;
        }

        res = (gpa_t)memmem(scan_buffer, PAGE_SIZE, SEARCH_BYTES, sizeof(SEARCH_BYTES) - 1);
        *scanned_count += 1;
        if (res) {
            res = (gpa_t)current_page + (gpa_t)(scan_buffer - res);
            break;
        }
    }

cleanup:
    if (scan_buffer) {
        kfree(scan_buffer);
    }
    return res;
}

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

        // get special registers to ensure guest is in kernel mode
		struct kvm_sregs *sregs = kzalloc(sizeof(struct kvm_sregs), GFP_KERNEL);
        CHECK(sregs, "failed to allocate sregs");

        res = get_sregs(vcpu, sregs);
        CHECK_OR(!res, free_sregs, "kvm_arch_vcpu_ioctl_get_sregs failed with %d", res);
        CHECK_OR(0 == (sregs->cs.base & 3), free_sregs, "guest is not in kernel mode");

        // get all mapped memory regions for this guest
        struct kvm_memslots *memslots = kvm->memslots[0];
        CHECK_OR(memslots, free_sregs, "memslots is NULL");

        println("searching for '" SEARCH_BYTES "' in the VM's entire memory space");
        struct timespec scan_time;
        getnstimeofday(&scan_time);

        gpa_t addr = 0;
        unsigned long pages_scanned = 0;
        struct kvm_memory_slot *memslot;
        kvm_for_each_memslot(memslot, memslots) {
            println("scanning memslot: userspace address=%lx, pages=%ld, guest page=%llu",
                    memslot->userspace_addr, memslot->npages, memslot->base_gfn);

            addr = map_and_search_pages(memslot->userspace_addr, memslot->npages, &pages_scanned);
            if (IS_ERR_VALUE(addr)) {
                println("falling back to kvm_guest_read()");
                addr = read_and_search_pages(memslot->userspace_addr, memslot->npages, &pages_scanned);
            }

            if (addr) {
                break;
            }
        }

        struct timespec now;
        getnstimeofday(&now);
        println("finished scanning %lu pages (~%lu MB) in %ld.%09ld seconds",
                pages_scanned,
                (pages_scanned * PAGE_SIZE) / (1 << 20),
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
