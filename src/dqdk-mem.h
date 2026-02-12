#ifndef DQDK_MEM_H
#define DQDK_MEM_H

#include <linux/mman.h>

#include "ctypes.h"
#include "dqdk-sys.h"

#define HUGEPAGE_2MB_SIZE 2097152UL
#define HUGEPAGE_1GB_SIZE 1073741824UL
#define HUGETLBFS_PATH "/dev/hugepages"
#define HUGETLB_CALC_2MB(size) ((u32)ceil(size * 1.0 / HUGEPAGE_2MB_SIZE))
#define HUGETLB_CALC_1GB(size) ((u32)ceil(size * 1.0 / HUGEPAGE_1GB_SIZE))

typedef struct {
    int numa_node;
} dqdk_mem_ctx_t;

u8* dqdk_huge_malloc(int numa_node, u64 size, page_size_t pagesz);
u8* dqdk_2mbhuge_malloc(int numa_node, u64 size);
u8* dqdk_malloc(u64 size, int flags);
int dqdk_free(u8* mem, u64 size);

#endif
