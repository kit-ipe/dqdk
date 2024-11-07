#ifndef DQDK_BLK_H
#define DQDK_BLK_H

#include <limits.h>
#include <time.h>

#include "ctypes.h"

#define FILE_BSIZE (1 * 1024 * 1024)
#define DQDK_BLK_QUEUE_DEPTH 16

typedef struct {
    u64 io_operations;
    u64 total_written;
    u64 time;
    int status;
    int blk_size;
} dqdk_blk_status_t;

dqdk_blk_status_t dqdk_blk_dump(const char* path, u32 blk_size, u64 totalsz, void* data);

#endif
