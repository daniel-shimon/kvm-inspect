#include <linux/printk.h>
#include <linux/string.h>

#include "utils.h"

void *memmem(void *haystack, size_t haystack_len, void *needle, size_t needle_len)
{
    if (haystack_len < needle_len) {
        eprintln("haystack length is smaller than needle length");
        return NULL;
    }

    void *addr = haystack;
    int scan_length = haystack_len;
    do {
        addr = memchr(addr, *(char *)needle, scan_length);
        if (!addr) {
            break;
        }

        scan_length = haystack_len - (addr - haystack);
        if (scan_length < needle_len) {
            break;
        }

        if (0 == memcmp(addr + 1, needle + 1, needle_len - 1)) {
            return addr;
        }

        addr += needle_len;
        scan_length -= needle_len;

    } while (scan_length);

    return NULL;
}
