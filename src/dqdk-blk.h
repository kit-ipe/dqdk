#ifndef DQDK_BLK_H
#define DQDK_BLK_H

#include <limits.h>
#include <time.h>
#include <liburing.h>

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

typedef struct {
    struct io_uring ring;
    u32 nb_entries;
} dqdk_blk_t;

dqdk_blk_t* dqdk_blk_init(int nbentries);
dqdk_blk_status_t dqdk_blk_dump(dqdk_blk_t* blk, const char* path, u32 blk_size, u64 totalsz, void* data);
int dqdk_blk_fini(dqdk_blk_t* blk);

#endif
