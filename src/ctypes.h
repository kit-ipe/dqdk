#ifndef DQDK_CTYPES
#define DQDK_CTYPES

#include <linux/types.h>

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

#define dqdk_always_inline inline __attribute__((always_inline))
#define packed __attribute__((packed))

#define dqdk_likely(x) __builtin_expect(!!(x), 1)
#define dqdk_unlikely(x) __builtin_expect(!!(x), 0)

static inline void dqdk_prefetch(const volatile void* p)
{
    asm volatile("prefetcht0 %[p]" : : [p] "m"(*(const volatile char*)p));
}

#define IGN_ARG(x) ((void)(x))

#endif
