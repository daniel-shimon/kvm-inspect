#ifndef UTILS_H
#define UTILS_H

#define println(fmt, ...) printk("[#] " fmt "\n", ##__VA_ARGS__)
#define eprintln(fmt, ...) printk("[!] " fmt "\n", ##__VA_ARGS__)

#define CHECK_OR(expr, cleanup, fmt, ...) do {  \
    if (!(expr)) {                              \
        eprintln(fmt, ##__VA_ARGS__);           \
        if (res == 0) {                         \
            res = -1;                           \
        }                                       \
        goto cleanup;                           \
    }                                           \
} while (0)

#define CHECK(expr, fmt, ...) CHECK_OR(expr, cleanup, fmt, ##__VA_ARGS__)

void *memmem(void *haystack, size_t haystack_len, void *needle, size_t needle_len);

#endif//UTILS_H
