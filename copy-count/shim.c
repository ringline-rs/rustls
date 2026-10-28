/* LD_PRELOAD shim counting memcpy and memmove calls of at least THRESH
 * bytes between cc_reset() and cc_get(). Smaller copies (headers, nonces)
 * are not counted. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>

static void *(*real_memcpy)(void *, const void *, size_t);
static void *(*real_memmove)(void *, const void *, size_t);
static uint64_t cpy_bytes, cpy_calls, mv_bytes, mv_calls;
static int armed;
#define THRESH 256

void cc_reset(void) {
    cpy_bytes = cpy_calls = mv_bytes = mv_calls = 0;
    armed = 1;
}

void cc_get(uint64_t *o) {
    o[0] = cpy_calls;
    o[1] = cpy_bytes;
    o[2] = mv_calls;
    o[3] = mv_bytes;
    armed = 0;
}

/* Used only before dlsym has resolved the real functions. */
static void *slow_copy(void *d, const void *s, size_t n) {
    unsigned char *dd = d;
    const unsigned char *ss = s;
    if (dd < ss) {
        for (size_t i = 0; i < n; i++) dd[i] = ss[i];
    } else {
        for (size_t i = n; i > 0; i--) dd[i - 1] = ss[i - 1];
    }
    return d;
}

void *memcpy(void *d, const void *s, size_t n) {
    if (!real_memcpy) {
        real_memcpy = dlsym(RTLD_NEXT, "memcpy");
        if (!real_memcpy) return slow_copy(d, s, n);
    }
    if (armed && n >= THRESH) {
        cpy_calls++;
        cpy_bytes += n;
    }
    return real_memcpy(d, s, n);
}

void *memmove(void *d, const void *s, size_t n) {
    if (!real_memmove) {
        real_memmove = dlsym(RTLD_NEXT, "memmove");
        if (!real_memmove) return slow_copy(d, s, n);
    }
    if (armed && n >= THRESH) {
        mv_calls++;
        mv_bytes += n;
    }
    return real_memmove(d, s, n);
}
