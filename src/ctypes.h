#ifndef DQDK_CTYPES
#define DQDK_CTYPES

#include <linux/types.h>

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

#define dqdk_always_inline // inline __attribute__((always_inline))
#define dqdk_packed __attribute__((packed))
#define dqdk_cache_aligned __attribute__((aligned(64)))

#define dqdk_likely(x) __builtin_expect(!!(x), 1)
#define dqdk_unlikely(x) __builtin_expect(!!(x), 0)

static inline void dqdk_prefetch(const volatile void* p)
{
    asm volatile("prefetcht0 %[p]" : : [p] "m"(*(const volatile char*)p));
}

#define ispower2(x) ((x) && (!(x & (x - 1))))
#define div_by_power2(x, n) ((x) >> (n))
#define modulo_power2(x, n) ((x) & ((1 << (n)) - 1))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define AVG(x, y) (((y) == 0) ? 0 : ((x) * 1.0 / (y)))
#define IGN_ARG(x) ((void)(x))

#endif
