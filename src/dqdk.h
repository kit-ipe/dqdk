#ifndef DQDK_TYPES_H
#define DQDK_TYPES_H

#include <linux/mman.h>
#include <linux/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <math.h>

#include "dlog.h"

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

#define always_inline inline __attribute__((always_inline))

#define HUGEPAGE_2MB_SIZE 2097152
#define HUGETLB_PATH "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
#define HUGETLB_CALC(size) ((u32)ceil(size / HUGEPAGE_2MB_SIZE))
#define HUGETLB_DIGITS 10

always_inline int get_hugepages()
{
    char buffer[HUGETLB_DIGITS] = { 0 };

    int fd = open(HUGETLB_PATH, O_RDONLY);
    if (fd < 0) {
        dlog_error2("open", fd);
        return -1;
    }

    int ret = read(fd, &buffer, HUGETLB_DIGITS);
    if (ret < 0) {
        dlog_error2("read", ret);
        return -1;
    }

    int nb_hugepages = atoi(buffer);
    close(fd);
    return nb_hugepages;
}

always_inline void set_hugepages(int nb_hugepages)
{
    char buffer[HUGETLB_DIGITS] = { 0 };

    int fd = open(HUGETLB_PATH, O_WRONLY);
    if (fd < 0) {
        dlog_error2("open", fd);
        return;
    }

    sprintf(buffer, "%d\n", nb_hugepages);

    int ret = write(fd, &buffer, 10);
    if (ret < 0) {
        dlog_error2("write", ret);
        return;
    }
    close(fd);
}

u8* huge_malloc(u64 size)
{
    int needed_hgpg = HUGETLB_CALC(size);
    int current_hgpg = get_hugepages();
    set_hugepages(current_hgpg + needed_hgpg);

    void* map = mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB, -1, 0);

    if (map == MAP_FAILED) {
        dlog_error2("huge_malloc", (int)(u64)map);
        return NULL;
    }

    return (u8*)map;
}

u64 clock_nsecs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#endif
