#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <math.h>

#include "dqdk-blk.h"

dqdk_blk_t* dqdk_blk_init(int nbentries)
{
    dqdk_blk_t* blk = (dqdk_blk_t*)malloc(sizeof(dqdk_blk_t));
    if (!blk)
        return NULL;

    blk->nb_entries = nbentries;
    if (io_uring_queue_init(nbentries, &blk->ring, 0) < 0) {
        free(blk);
        return NULL;
    }
    return blk;
}

dqdk_blk_status_t dqdk_blk_dump(dqdk_blk_t* blk, const char* path, u32 blk_size, u64 totalsz, void* data)
{
    u64 total_wr = 0, total_wr_snapshot = 0;
    int total_blocks = 0, ret = 0;
    struct io_uring_cqe* cqe = NULL;
    time_t t0 = 0, t1 = 0;

    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        perror("open");
        ret = errno;
        goto exit;
    }

    t0 = time(NULL);

    while (total_wr_snapshot != totalsz) {
        u64 rem_blocks = (u64)ceil((totalsz - total_wr) * 1.0 / blk_size);
        int nentries = rem_blocks > blk->nb_entries ? blk->nb_entries : rem_blocks;

        for (int i = 0; i < nentries; i++) {
            int bytes = (totalsz - total_wr) > blk_size ? blk_size : (totalsz - total_wr);
            struct io_uring_sqe* sqe = io_uring_get_sqe(&blk->ring);
            io_uring_prep_write(sqe, fd, data, bytes, total_wr);
            total_wr += bytes;
        }

        nentries = io_uring_submit(&blk->ring);
        if (ret < 0)
            goto exit;

        for (int i = 0; i < nentries; i++) {
            ret = io_uring_wait_cqe(&blk->ring, &cqe);
            if (ret < 0)
                goto exit;

            if (cqe->res < 0) {
                ret = cqe->res;
                goto exit;
            }

            io_uring_cqe_seen(&blk->ring, cqe);
            total_blocks++;
        }

        total_wr_snapshot = total_wr;
    }

    if (fsync(fd) < 0 || close(fd) < 0) {
        ret = errno;
        goto exit;
    }

    t1 = time(NULL);

exit:
    dqdk_blk_status_t stats = {
        .status = ret,
        .total_written = total_wr_snapshot,
        .io_operations = total_blocks,
        .time = (t1 - t0) < 0 ? 0 : (t1 - t0),
        .blk_size = blk_size,
    };

    return stats;
}

int dqdk_blk_fini(dqdk_blk_t* blk)
{
    if (!blk)
        return -1;

    io_uring_queue_exit(&blk->ring);
    free(blk);

    return 0;
}
