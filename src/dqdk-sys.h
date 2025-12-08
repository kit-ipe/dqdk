#ifndef DQDK_SYS_H
#define DQDK_SYS_H

#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/mman.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>
#include <net/if.h>

#include "dlog.h"
#include "ctypes.h"

#define HUGEPAGE_2MB_SIZE 2097152UL
#define HUGEPAGE_1GB_SIZE 1073741824UL
#define HUGETLB_PATH_2MB "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
#define HUGETLB_PATH_1GB "/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages"
#define HUGETLBFS_PATH "/dev/hugepages"
#define HUGETLB_CALC_2MB(size) ((u32)ceil(size * 1.0 / HUGEPAGE_2MB_SIZE))
#define HUGETLB_CALC_1GB(size) ((u32)ceil(size * 1.0 / HUGEPAGE_1GB_SIZE))
#define BAD_CLOCK ((u64) - 1)
#define INT_BUFFER 100
#define STRING_BUFFER 1024

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ntoh24b(x) (((x & 0xff) << 16) | (((x >> 8) & 0xff) << 8) | ((x >> 16) & 0xff))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ntoh24b(x) (x)
#else
#error "Unsupported Endianess"
#endif

typedef enum {
    PAGE_4KB = 0,
    PAGE_2MB = MAP_HUGE_2MB,
    PAGE_1GB = MAP_HUGE_1GB,
} page_size_t;

typedef struct {
    u32 irq;
    u32 interrupts;
} irq_interrupts_t;

typedef struct {
    u32 nbirqs;
    irq_interrupts_t* interrupts;
} interrupts_t;

char* sys_read_string(const char* path);
int sys_read_uint(const char* path);
int sys_write_int(const char* path, int value);
int nic_numa_node(const char* ifname);
char* get_numa_hugepages_path(int numanode, page_size_t pagesz);
int set_hugepages(int device_numanode, int howmany, page_size_t pagesz);
int get_hugepages(int device_numanode, page_size_t pagesz);
dqdk_always_inline u64 clock_nsecs(clockid_t clock);
dqdk_always_inline int clock_nsleep(u64 nsecs);
void nic_set_irq_affinity(int irq, int cpu);
interrupts_t* nic_get_interrupts(char* irqstr, u32 nprocs);
int is_smt();
int cpu_smt_sibling(int cpu);
int dqdk_get_link_speed(const char* iface);
struct tm* getlocaltime(void);

#define clock_nsecs_real() clock_nsecs(CLOCK_REALTIME)
#define clock_nsecs_mono() clock_nsecs(CLOCK_MONOTONIC)

#define popcountl(x) __builtin_popcountl(x)
#define log2l(x) (31 - __builtin_clz(x))

#endif
