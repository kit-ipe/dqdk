#include <sys/mman.h>

#include "dqdk-mem.h"
#include "dqdk-sys.h"
#include "dlog.h"

int dqdk_free(u8* mem, u64 size)
{
    return munmap(mem, size);
}

static u8* dqdk_map(u64 size, int flags, int fd)
{
    void* map = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, fd, 0);

    if (map == MAP_FAILED) {
        dlog_error2("dqdk_map", (int)(u64)map);
        dlog_errorv("Cannot allocate memory of size=%llu and flags=0x%08x", size, flags);
        return NULL;
    }

    if (mlock(map, size) < 0) {
        dqdk_free(map, size);
        map = NULL;
    }

    return (u8*)map;
}

u8* dqdk_malloc(u64 size, int flags)
{
    return dqdk_map(size, MAP_PRIVATE | MAP_ANONYMOUS | flags, -1);
}

u8* dqdk_huge_malloc(int numa_node, u64 size, page_size_t pagesz)
{
    int additional_pages = 0, needed_hgpg = 0;

    switch (pagesz) {
    case PAGE_2MB:
        additional_pages = HUGETLB_CALC_2MB(size);
        break;
    case PAGE_1GB:
        additional_pages = HUGETLB_CALC_1GB(size);
        break;

    case PAGE_4KB:
    default:
        return NULL;
    }

    // struct stat st;
    // if (stat(HUGETLBFS_PATH, &st) == 0 && S_ISDIR(st.st_mode)) {
    //     char hugepage_filename[PATH_MAX];
    //     snprintf(hugepage_filename, PATH_MAX, HUGETLBFS_PATH "/dqdk%d", atomic_fetch_add_explicit(&ctx->huge_allocations, 1, memory_order_relaxed));
    //     dlog_infov("Allocating huge pages memory to %s", hugepage_filename);
    //     int fd = open(hugepage_filename, O_CREAT | O_RDWR, 0755);
    //     if (fd < 0) {
    //         dlog_error2("open", fd);
    //         return NULL;
    //     }

    //     if (ftruncate(fd, size) < 0) {
    //         dlog_error2("ftruncate", -1);
    //         return NULL;
    //     }

    //     u8* map = dqdk_map(ctx, size, MAP_PRIVATE | MAP_HUGETLB | pagesz, fd);
    //     close(fd);
    //     unlink(hugepage_filename);
    //     return map;
    // }

    needed_hgpg = get_hugepages(numa_node, pagesz) + additional_pages;
    int page = set_hugepages(numa_node, needed_hgpg, pagesz);
    dlog_infov("Reserved huge pages are %d now", page);

    return dqdk_malloc(size, MAP_HUGETLB | pagesz);
}

u8* dqdk_2mbhuge_malloc(int numa_node, u64 size)
{
    return dqdk_huge_malloc(numa_node, size, PAGE_2MB);
}
