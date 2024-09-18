#include <stdio.h>
#include <stdlib.h>
#include <liburing.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#define QUEUE_DEPTH 16
#define FILE_SIZE (10UL * 1024 * 1024 * 1024)
#define FILE_BSIZE (1 * 1024 * 1024)
#define VECTOR_SIZE QUEUE_DEPTH

int main(int argc, char* argv[])
{
    off_t total_wr = 0;
    int total_blocks = 0, ret = 0;
    struct io_uring ring;
    int sync = 0;

    if (argc > 1 && !strncmp(argv[1], "sync", 5))
        sync = 1;

    int fd = open("./iouring-dump", O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        perror("open");
        goto exit;
    }

    time_t t0 = time(NULL);
    if (!sync) {
        io_uring_queue_init(QUEUE_DEPTH, &ring, 0);

        struct io_uring_cqe* cqes[QUEUE_DEPTH] = { 0 };
        struct io_uring_cqe* cqe = NULL;

        while (total_wr != FILE_SIZE) {
            for (int i = 0; i < QUEUE_DEPTH; i++) {
                struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
                void* buffer = malloc(FILE_BSIZE);
                io_uring_prep_write(sqe, fd, buffer, FILE_BSIZE, total_wr);
                io_uring_sqe_set_data(sqe, buffer);
            }

            ret = io_uring_submit(&ring);
            if (ret < 0) {
                printf("io_uring_submit returned %d\n", ret);
                return ret;
            }

            int old_blocks = total_blocks;
            for (int i = 0; i < QUEUE_DEPTH; i++) {
                if (io_uring_wait_cqe(&ring, &cqe) < 0) {
                    printf("io_uring_wait_cqe failed\n");
                    break;
                }

                if (cqe->res < 0) {
                    printf("Async writev failed with result=%d\n", cqes[i]->res);
                    continue;
                }
                void* buffer = io_uring_cqe_get_data(cqe);
                io_uring_cqe_seen(&ring, cqe);
                free(buffer);

                total_blocks++;
            }
            total_wr += (total_blocks - old_blocks) * FILE_BSIZE;
        }
        /* Call the clean-up function. */
        io_uring_queue_exit(&ring);
    } else {
        while (total_wr != FILE_SIZE) {
            int old_blocks = total_blocks;
            for (int i = 0; i < QUEUE_DEPTH; i++) {
                void* buffer = malloc(FILE_BSIZE);
                ret = write(fd, buffer, FILE_BSIZE);
                if (ret < 0) {
                    perror("write");
                    return ret;
                }
                total_blocks++;
                free(buffer);
            }

            total_wr += (total_blocks - old_blocks) * FILE_BSIZE;
        }
    }

    fsync(fd);
    close(fd);
    time_t t1 = time(NULL);
    printf("Total Size=%luB | Total Time=%lu | Total Blocks=%d | Average Throughput=%.3f GB/sec\n",
        FILE_SIZE, t1 - t0, total_blocks, FILE_SIZE / ((t1 - t0) * 1e9));
exit:
    return 0;
}