#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <math.h>
#include <unistd.h>
#include <errno.h>

#include "dqdk-blk.h"

dqdk_blk_status_t dqdk_blk_dump(const char* path, u32 blk_size, u64 totalsz, void* data)
{
    u64 total_wr = 0;
    int total_blocks = 0, ret = 0;
    time_t t0 = 0, t1 = 0;

    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        perror("open");
        ret = errno;
        goto exit;
    }

    t0 = time(NULL);

    while (total_wr != totalsz) {
        int wr_bytes = (totalsz - total_wr) > blk_size ? blk_size : (totalsz - total_wr);
        ret = write(fd, data + total_wr, wr_bytes);
        if (ret < 0) {
            ret = errno;
            goto exit;
        }
        total_wr += ret;
        total_blocks++;
    }

    ret = 0;
    if (fsync(fd) < 0 || close(fd) < 0) {
        ret = errno;
        goto exit;
    }

    t1 = time(NULL);

exit:
    dqdk_blk_status_t stats = {
        .status = ret,
        .total_written = total_wr,
        .io_operations = total_blocks,
        .time = (t1 - t0) < 0 ? 0 : (t1 - t0),
        .blk_size = blk_size,
    };

    return stats;
}
