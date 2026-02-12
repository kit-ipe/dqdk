#include <stdio.h>
#include <string.h>
#include <time.h>

#define MEMCPY_TEST

#include "../src/tristan-dummy.h"
int main()
{
    char dst[3392];
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    memcpy(dst, nbins256, 3392);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("t1-t0 = %lu\n", t1.tv_nsec - t0.tv_nsec);
    return 0;
}
