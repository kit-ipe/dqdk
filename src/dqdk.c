// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/icmp.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <netinet/udp.h>
#include <math.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <time.h>

#include "dqdk.h"
#include "tcpip/ipv4.h"
#include "tcpip/udp.h"

#define UMEM_LEN (XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE

#define MAX_QUEUES 16
#define UMEM_SIZE (UMEM_LEN * FRAME_SIZE)
#define FILLQ_LEN UMEM_LEN
#define COMPQ_LEN XSK_RING_CONS__DEFAULT_NUM_DESCS

struct xsk_stat {
    u64 rcvd_frames;
    u64 rcvd_pkts;
    u64 fail_polls;
    u64 timeout_polls;
    u64 rx_empty_polls;
    u64 rx_fill_fail_polls;
    u64 invalid_ip_pkts;
    u64 invalid_udp_pkts;
    u64 runtime;
    struct xdp_statistics xstats;
};

typedef struct {
    struct xsk_umem* umem;
    struct xsk_ring_prod fq0;
    struct xsk_ring_cons cq0;
    u32 nbfqs;
    u32 size;
    void* buffer;
} umem_info;

typedef struct {
    u32 index;
    u32 queue_id;
    struct xsk_socket* socket;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    umem_info* umem_info;
    struct xsk_ring_prod* fill_ring;
    struct xsk_ring_cons* comp_ring;
    u32 libbpf_flags;
    u32 xdp_flags;
    u16 bind_flags;
    u32 batch_size;
    struct xsk_stat stats;
} xsk_info;

u32 break_flag = 0;

static void* umem_buffer_create(u32 size)
{
#ifdef NO_HGPG
    return mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#else
    return huge_malloc(size);
#endif
}

static umem_info* umem_info_create(u32 nbfqs)
{
    umem_info* info = (umem_info*)calloc(1, sizeof(umem_info));

    info->size = UMEM_SIZE * nbfqs;
    info->buffer = umem_buffer_create(info->size);
    if (info->buffer == NULL) {
        dlog_error2("umem_buffer_create", 0);
        return NULL;
    }

    info->umem = NULL;
    info->nbfqs = nbfqs;
    return info;
}

static void umem_info_free(umem_info* info)
{
    if (info != NULL) {
        munmap(info->buffer, info->size);
        xsk_umem__delete(info->umem);
    }
}

static int umem_configure(umem_info* umem)
{
    int ret;

    if (umem == NULL) {
        dlog_error("Invalid umem buffer: NULL");
        return EINVAL;
    }

    const struct xsk_umem_config cfg = {
        .fill_size = FILLQ_LEN,
        .comp_size = COMPQ_LEN,
        .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
#ifdef UMEM_UNALIGNED
        .flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG
#else
        .flags = 0
#endif
    };

    ret = xsk_umem__create(&umem->umem, umem->buffer, umem->size,
        &umem->fq0, &umem->cq0, &cfg);
    if (ret) {
        dlog_error2("xsk_umem__create", ret);
        return ret;
    }

    return 0;
}

static int xsk_configure(xsk_info* xsk, const char* ifname)
{
    int ret = 0;
    u32 nbfqs = xsk->umem_info->nbfqs;

    const struct xsk_socket_config xsk_config = {
        .rx_size = FILLQ_LEN,
        .tx_size = COMPQ_LEN,
        .bind_flags = xsk->bind_flags,
        .libbpf_flags = xsk->libbpf_flags,
        .xdp_flags = xsk->xdp_flags
    };

    struct xsk_ring_prod* fq = NULL;
    struct xsk_ring_cons* cq = NULL;

    if (nbfqs == 1) {
        fq = &xsk->umem_info->fq0;
    } else {
        if (xsk->fill_ring == NULL) {
            xsk->fill_ring = calloc(1, sizeof(struct xsk_ring_prod));
        }

        fq = xsk->fill_ring;
    }

    if (nbfqs == 1) {
        cq = &xsk->umem_info->cq0;
    } else {
        if (xsk->comp_ring == NULL) {
            xsk->comp_ring = calloc(1, sizeof(struct xsk_ring_cons));
        }

        cq = xsk->comp_ring;
    }

    ret = xsk_socket__create_shared(&xsk->socket, ifname, xsk->queue_id,
        xsk->umem_info->umem, &xsk->rx, NULL, fq, cq, &xsk_config);
    if (ret) {
        dlog_error2("xsk_socket__create", ret);
        return ret;
    }

    u32 sockopt = 1;
    ret = setsockopt(xsk_socket__fd(xsk->socket), SOL_SOCKET, SO_PREFER_BUSY_POLL,
        (void*)&sockopt, sizeof(sockopt));
    if (ret) {
        dlog_error2("setsockopt(SO_PREFER_BUSY_POLL)", ret);
        return ret;
    }

    sockopt = 20;
    ret = setsockopt(xsk_socket__fd(xsk->socket), SOL_SOCKET, SO_BUSY_POLL,
        (void*)&sockopt, sizeof(sockopt));
    if (ret) {
        dlog_error2("setsockopt(SO_BUSY_POLL)", ret);
        return ret;
    }

    sockopt = xsk->batch_size;
    ret = setsockopt(xsk_socket__fd(xsk->socket), SOL_SOCKET, SO_BUSY_POLL_BUDGET,
        (void*)&sockopt, sizeof(sockopt));
    if (ret) {
        dlog_error2("setsockopt(SO_BUSY_POLL_BUDGET)", ret);
        return ret;
    }

    return 0;
}

static int fq_ring_configure(xsk_info* xsk)
{
    // push all frames to fill ring
    u32 idx = 0, ret, nbfqs = xsk->umem_info->nbfqs, fqlen = FILLQ_LEN;

    struct xsk_ring_prod* fq = nbfqs == 1 ? &xsk->umem_info->fq0
                                          : xsk->fill_ring;

    ret = xsk_ring_prod__reserve(fq, fqlen, &idx);
    if (ret != fqlen) {
        dlog_error2("xsk_ring_prod__reserve", ret);
        return EIO;
    }

    // fill addresses
    u32 base = nbfqs != 1 ? xsk->index * UMEM_SIZE : 0;
    for (u32 i = 0; i < fqlen; i++) {
        *xsk_ring_prod__fill_addr(fq, idx++) = base + (i * FRAME_SIZE);
    }

    xsk_ring_prod__submit(fq, fqlen);
    return 0;
}

always_inline u8* process_frame(xsk_info* xsk, u8* buffer, u32 len)
{
    struct ethhdr* frame = (struct ethhdr*)buffer;
    u16 ethertype = ntohs(frame->h_proto);

    xsk->stats.rcvd_frames++;
    if (ethertype != ETH_P_IP) {
        return NULL;
    }

    xsk->stats.rcvd_pkts++;
    struct iphdr* packet = (struct iphdr*)(frame + 1);
    if (packet->version != 4) {
        return NULL;
    }

    if (!ip4_audit(packet, len - sizeof(struct ethhdr))) {
        xsk->stats.invalid_ip_pkts++;
        return NULL;
    }

    u32 iphdrsz = ip4_get_header_size(packet);
    u32 udplen = ntohs(packet->tot_len) - iphdrsz;
    struct udphdr* udp = (struct udphdr*)(((u8*)packet) + iphdrsz);
    if (!udp_audit(udp, packet->saddr, packet->daddr, udplen)) {
        xsk->stats.invalid_udp_pkts++;
        return NULL;
    }

    return (u8*)(udp + 1);
}

always_inline int xdp_udpip(xsk_info* xsk, umem_info* umem)
{
    u32 idx_rx = 0, idx_fq = 0;
    struct xsk_ring_prod* fq = umem->nbfqs == 1 ? &umem->fq0 : xsk->fill_ring;

    int rcvd = xsk_ring_cons__peek(&xsk->rx, xsk->batch_size, &idx_rx);
    if (!rcvd) {
        if (xsk_ring_prod__needs_wakeup(fq)) {
            xsk->stats.rx_empty_polls++;
            recvfrom(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }

        return ECOMM;
    }

    int ret = xsk_ring_prod__reserve(fq, rcvd, &idx_fq);
    while (ret != rcvd) {
        if (ret < 0) {
            return -ret;
        }

        if (xsk_ring_prod__needs_wakeup(fq)) {
            xsk->stats.rx_fill_fail_polls++;
            recvfrom(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }

        ret = xsk_ring_prod__reserve(fq, rcvd, &idx_fq);
    }

    for (int i = 0; i < rcvd; i++) {
        u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
#ifdef UMEM_UNALIGNED
        u64 orig = xsk_umem__extract_addr(addr);
        addr = xsk_umem__add_offset_to_addr(addr);
#endif

#ifdef RX_DROP
        xsk_umem__get_data(umem->buffer, addr);
#else
        u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->len;
        u8* frame = xsk_umem__get_data(umem->buffer, addr);
        u8* data = process_frame(xsk, frame, len);

        (void)data;
#endif
        idx_rx++;
#ifdef UMEM_UNALIGNED
        *xsk_ring_prod__fill_addr(fq, idx_fq) = orig;
#endif
        idx_fq++;
    }

#ifdef RX_DROP
    xsk->stats.rcvd_frames += rcvd;
#endif

    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk_ring_prod__submit(fq, rcvd);
    return 0;
}

struct rx_ctx {
    xsk_info* xsks;
    u32 count;
    u8 pollmode;
    u8 shared_umem;
};

#define POLL_TIMEOUT 1000

void* poll_rx(void* rxctx_ptr)
{
    struct rx_ctx* ctx = (struct rx_ctx*)rxctx_ptr;
    xsk_info* xsks = ctx->xsks;
    u64 t0, t1;

    switch (ctx->pollmode) {
    case DQDK_RCV_POLL:
        struct pollfd* fds = (struct pollfd*)calloc(ctx->count, sizeof(struct pollfd));

        for (size_t i = 0; i < ctx->count; i++) {
            fds[i].fd = xsk_socket__fd(xsks[i].socket);
            fds[i].events = POLLIN;
        }

        t0 = clock_nsecs();
        while (!break_flag) {
            int ret = poll(fds, ctx->count, POLL_TIMEOUT);
            if (ret < 0) {
                dlog_error2("poll", ret);
                continue;
            } else if (ret == 0) {
                dlog_info("[Poll] Timeout");
                continue;
            } else {
                for (size_t i = 0; i < ctx->count; i++) {
                    ret = xdp_udpip(&xsks[i], xsks[i].umem_info);
                }
            }
        }
        t1 = clock_nsecs();
        free(fds);
        break;
    case DQDK_RCV_RTC:
        t0 = clock_nsecs();
        while (!break_flag) {
            for (size_t i = 0; i < ctx->count; i++) {
                xdp_udpip(&xsks[i], xsks[i].umem_info);
            }
        }
        t1 = clock_nsecs();
        break;
    }

    socklen_t socklen = sizeof(struct xdp_statistics);
    for (size_t i = 0; i < ctx->count; i++) {
        xsks[i].stats.runtime = t1 - t0;
        int ret = getsockopt(xsk_socket__fd(xsks[i].socket), SOL_XDP,
            XDP_STATISTICS, &xsks[i].stats.xstats, &socklen);
        if (ret) {
            dlog_error2("getsockopt(XDP_STATISTICS)", ret);
        }
    }

    return NULL;
}

void signal_handler(int sig)
{
    switch (sig) {
    case SIGINT:
    case SIGTERM:
    case SIGABRT:
    case SIGUSR1:
        break_flag = 1;
        break;
    default:
        break;
    }
}

int infoprint(enum libbpf_print_level level,
    const char* format, va_list ap)
{
    (void)level;
    return vfprintf(stderr, format, ap);
}

#define AVG_PPS(pkts, rt) (pkts * 1e9 / rt)

void stats_dump(struct xsk_stat* stats)
{
    printf("    Total runtime (ns):     %llu\n"
           "    Received Frames:        %llu\n"
           "    Average FPS:            %f\n"
           "    Received Packets:       %llu\n"
           "    Average PPS:            %f\n"
           "    Invalid L3 Packets:     %llu\n"
           "    Invalid L4 Packets:     %llu\n"
           "    Failed Polls:           %llu\n"
           "    Timeout Polls:          %llu\n"
           "    XSK Fill Fail Polls:    %llu\n"
           "    XSK RXQ Empty:          %llu\n"
           "    XSK RX Dropped:         %llu\n"
           "    XSK RX FillQ Empty:     %llu\n"
           "    XSK RX Invalid Descs:   %llu\n"
           "    XSK RX Ring Full:       %llu\n"
           "    XSK TX Invalid Descs:   %llu\n"
           "    XSK TX Ring Empty:      %llu\n",
        stats->runtime, stats->rcvd_frames,
        AVG_PPS(stats->rcvd_frames, stats->runtime), stats->rcvd_pkts,
        AVG_PPS(stats->rcvd_pkts, stats->runtime), stats->invalid_ip_pkts,
        stats->invalid_udp_pkts, stats->fail_polls, stats->timeout_polls,
        stats->rx_fill_fail_polls, stats->rx_empty_polls,
        stats->xstats.rx_dropped, stats->xstats.rx_fill_ring_empty_descs,
        stats->xstats.rx_invalid_descs, stats->xstats.rx_ring_full,
        stats->xstats.tx_invalid_descs, stats->xstats.tx_ring_empty_descs);
}

void xsk_stats_dump(xsk_info* xsk)
{
    printf("XSK %u on Queue %u Statistics:\n", xsk->index, xsk->queue_id);
    stats_dump(&xsk->stats);
}

#define XDP_FILE_XSK "./bpf/xsk.bpf.o"
#define XDP_FILE_RR2 "./bpf/rr2.bpf.o"
#define XDP_FILE_RR4 "./bpf/rr4.bpf.o"
#define XDP_FILE_RR8 "./bpf/rr8.bpf.o"

int main(int argc, char** argv)
{
#ifdef RX_DROP
    dlog_info("RX_DROP Compilation!");
#else
    dlog_info("UDP Compilation!");
#endif

#ifdef NO_HGPG
    dlog_info("NO_HGPG Compilation!");
#else
    dlog_info("HGPG Compilation!");
#endif

    char* opt_ifname = NULL;
    enum xdp_attach_mode opt_mode = XDP_MODE_NATIVE;
    u32 opt_batchsize = 64, opt_queues[MAX_QUEUES] = { -1 },
        opt_irqs[MAX_QUEUES] = { -1 }, opt_shared_umem = 0;
    struct itimerspec opt_duration = {
        .it_interval.tv_sec = DQDK_DURATION,
        .it_interval.tv_nsec = 0,
        .it_value.tv_sec = opt_duration.it_interval.tv_sec,
        .it_value.tv_nsec = 0
    };
    u8 opt_needs_wakeup = 0, opt_verbose = 0, opt_zcopy = 1,
       opt_pollmode = DQDK_RCV_POLL, opt_affinity = 0;

    int ifindex, ret, opt;
    u32 nbqueues = 0, nbirqs = 0, nprocs = get_nprocs();
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    interrupts_t *before_interrupts = NULL, *after_interrupts = NULL;
    struct xdp_program* kern_prog = NULL;
    struct xdp_options xdp_opts;
    char* xdp_filename = XDP_FILE_XSK;
    cpu_set_t* cpusets = NULL;
    xsk_info* xsks = NULL;
    struct rx_ctx* ctxs = NULL;
    timer_t timer;
    socklen_t socklen;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGUSR1, signal_handler);

    while ((opt = getopt(argc, argv, "a:b:cd:i:l:m:p:q:s:vw")) != -1) {
        switch (opt) {
        case 'a':
            // mapping to queues is 1-to-1 e.g. first irq to first queue...
            opt_affinity = 1;
            if (strchr(optarg, ',') == NULL) {
                nbirqs = 1;
                opt_irqs[0] = atoi(optarg);
            } else {
                char *delimiter = NULL, *cursor = optarg;
                u32 irq = -1;
                do {
                    irq = strtol(cursor, &delimiter, 10);
                    if (errno != 0
                        || cursor == delimiter
                        || (delimiter[0] != ',' && delimiter[0] != '\0')) {
                        dlog_error("Invalid IRQ string");
                        goto cleanup;
                    }

                    cursor = delimiter + 1;
                    opt_irqs[nbirqs++] = irq;
                } while (delimiter[0] != '\0');
            }
            break;
        case 'd':
            opt_duration.it_interval.tv_sec = atoi(optarg);
            opt_duration.it_interval.tv_nsec = 0;
            opt_duration.it_value.tv_sec = opt_duration.it_interval.tv_sec;
            opt_duration.it_value.tv_nsec = 0;
            break;
        case 'i':
            opt_ifname = optarg;
            ifindex = if_nametoindex(opt_ifname);
            break;
        case 'q':
            if (strchr(optarg, '-') == NULL) {
                nbqueues = 1;
                opt_queues[0] = atoi(optarg);
            } else {
                char* delimiter = NULL;
                u32 start = strtol(optarg, &delimiter, 10), end;
                if (delimiter != optarg) {
                    end = strtol(++delimiter, &delimiter, 10);
                } else {
                    dlog_error("Invalid queue range. Accepted: 1,2,3 or 1");
                    exit(EXIT_FAILURE);
                }

                nbqueues = (end - start) + 1;
                if (nbqueues > MAX_QUEUES) {
                    dlog_errorv("Too many queues. Maximum is %d", MAX_QUEUES);
                    exit(EXIT_FAILURE);
                }

                for (u32 idx = 0; idx < nbqueues; ++idx) {
                    opt_queues[idx] = start + idx;
                }
            }
            break;
        case 'm':
            if (strcmp("native", optarg) == 0) {
                opt_mode = XDP_MODE_NATIVE;
            } else if (strcmp("generic", optarg) == 0) {
                opt_mode = XDP_MODE_SKB;
            } else {
                dlog_error("Invalid XDP Mode");
                exit(EXIT_FAILURE);
            }
            break;
        case 'c':
            opt_zcopy = 0;
            break;
        case 'v':
            opt_verbose = 1;
            break;
        case 'b':
            opt_batchsize = atoi(optarg);
            break;
        case 'w':
            opt_needs_wakeup = 1;
            break;
        case 'p':
            if (strcmp("poll", optarg) == 0) {
                opt_pollmode = DQDK_RCV_POLL;
            } else if (strcmp("rtc", optarg) == 0) {
                opt_pollmode = DQDK_RCV_RTC;
            } else {
                dlog_error("Invalid Poll Mode");
                exit(EXIT_FAILURE);
            }
            break;
        case 's':
            opt_shared_umem = atoi(optarg);
            break;
        default:
            dlog_error("Invalid Arg\n");
            exit(EXIT_FAILURE);
        }
    }

    if (opt_ifname == NULL || nbqueues == 0) {
        dlog_error("Invalid interface name or number of queues");
        goto cleanup;
    }

    if (opt_affinity) {
        if (opt_pollmode != DQDK_RCV_RTC) {
            dlog_error("IRQ and thread affinity is only possible in RTC mode using command option: -p rtc ");
            goto cleanup;
        }

        if (nbirqs != nbqueues) {
            dlog_error("IRQs and number of queues must be equal");
            goto cleanup;
        }

        if (nbirqs > nprocs) {
            dlog_error("IRQs should be smaller or equal to number of processors");
            goto cleanup;
        }
    }

    switch (opt_mode) {
    case XDP_MODE_SKB:
        dlog_info("XDP generic mode is activated.");
        break;
    case XDP_MODE_NATIVE:
        dlog_info("XDP driver mode is activated.");
        break;
    case XDP_MODE_HW:
        dlog_info("XDP HW-Offloading is activated.");
        break;
    default:
        break;
    }

    if (opt_zcopy && opt_mode == XDP_MODE_SKB) {
        dlog_info("Turning off zero-copy for XDP generic mode");
        opt_zcopy = 0;
    }

    if (opt_verbose) {
        libbpf_set_print(infoprint);
    }

    switch (opt_pollmode) {
    case DQDK_RCV_POLL:
        dlog_info("Multithreading is turned off. Polling all sockets...");
        break;
    case DQDK_RCV_RTC:
        dlog_info("One fill queue per socket in run-to-completion mode");
        break;
    default:
        break;
    }

    u32 nbxsks = opt_shared_umem > 1 ? opt_shared_umem : nbqueues;
    char queues[4 * MAX_QUEUES] = { 0 };
    char* queues_format = queues;
    for (u32 i = 0; i < nbqueues; i++) {
        ret = (i == nbqueues - 1) ? snprintf(queues_format, 2, "%d", opt_queues[i])
                                  : snprintf(queues_format, 4, "%d, ", opt_queues[i]);
        queues_format += ret;
    }

    if (opt_shared_umem > 1) {
        if (opt_shared_umem > 8) {
            dlog_error("No more than 8 sockets are supported");
            goto cleanup;
        }

        if (nbqueues == 1 && !is_power_of_2(opt_shared_umem)) {
            dlog_error("Number of shared sockets per one queue should a power of 2");
            goto cleanup;
        }

        if (nbqueues != 1) {
            nbxsks = opt_shared_umem = nbqueues;
            dlog_info("Per-queue routing to XSK.");
        } else {
            dlog_info("Round robin routing to XSKs.");
            u32 qid = opt_queues[0];

            switch (nbxsks) {
            case 2:
                xdp_filename = XDP_FILE_RR2;
                break;
            case 4:
                xdp_filename = XDP_FILE_RR4;
                break;
            case 8:
                xdp_filename = XDP_FILE_RR8;
                break;
            }

            for (size_t i = 0; i < nbxsks; i++) {
                opt_queues[i] = qid;
            }

            dlog_infov("Working %d XSKs with shared UMEM on queue %s", nbqueues, queues);
        }
    } else {
        dlog_info("Per-queue routing to XSK.");
        dlog_infov("Working %d XSKs on queues: %s", nbqueues, queues);
    }

    if (opt_affinity && opt_pollmode == DQDK_RCV_RTC) {
        dlog_info_head("IRQ-to-Queue Mappings: ");
        for (size_t i = 0; i < nbirqs; i++) {
            if (i != nbirqs - 1) {
                dlog_info_print("%d-%d, ", opt_irqs[i], opt_queues[i]);
            } else {
                dlog_info_print("%d-%d", opt_irqs[i], opt_queues[i]);
            }
        }
        dlog_info_exit();
    }

    if ((ret = setrlimit(RLIMIT_MEMLOCK, &rlim))) {
        dlog_error2("setrlimit", ret);
        goto cleanup;
    }

    kern_prog = xdp_program__open_file(xdp_filename, NULL, NULL);
    ret = xdp_program__attach(kern_prog, ifindex, opt_mode, 0);
    if (ret) {
        dlog_error2("xdp_program__attach", ret);
        goto cleanup;
    }

    struct bpf_object* obj = xdp_program__bpf_obj(kern_prog);
    int mapfd = bpf_object__find_map_fd_by_name(obj, "xsks_map");

    pthread_t* xsk_workers = NULL;
    pthread_attr_t* xsk_worker_attrs = NULL;
    if (IS_THREADED(opt_pollmode, nbqueues)) {
        xsk_workers = (pthread_t*)calloc(nbxsks, sizeof(pthread_t));
        xsk_worker_attrs = (pthread_attr_t*)calloc(nbxsks, sizeof(pthread_attr_t));
        ctxs = (struct rx_ctx*)calloc(nbxsks, sizeof(struct rx_ctx));
        if (opt_affinity) {
            cpusets = (cpu_set_t*)calloc(nbxsks, sizeof(cpu_set_t));
        }
    }

    xsks = (xsk_info*)calloc(nbxsks, sizeof(xsk_info));
    umem_info* shared_umem = NULL;

    if (opt_shared_umem > 1) {
        shared_umem = nbqueues != 1 ? umem_info_create(nbxsks) : umem_info_create(1);
        umem_configure(shared_umem);
    }

    struct sigevent sigv;
    sigv.sigev_notify = SIGEV_SIGNAL;
    sigv.sigev_signo = SIGUSR1;
    timer_create(CLOCK_MONOTONIC, &sigv, &timer);
    timer_settime(timer, 0, &opt_duration, NULL);

    before_interrupts = nic_get_interrupts(opt_ifname, nprocs);
    for (u32 i = 0; i < nbxsks; i++) {

        xsks[i].batch_size = opt_batchsize;
        xsks[i].libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
        xsks[i].bind_flags = (opt_zcopy ? XDP_ZEROCOPY : XDP_COPY)
            | (opt_needs_wakeup ? XDP_USE_NEED_WAKEUP : 0);

        if (i != 0 && opt_shared_umem > 1) {
            xsks[i].bind_flags = XDP_SHARED_UMEM;
        }

        xsks[i].xdp_flags = 0;
        xsks[i].queue_id = opt_queues[i];
        xsks[i].index = i;

        if (opt_shared_umem > 1) {
            xsks[i].umem_info = shared_umem;
        } else {
            xsks[i].umem_info = umem_info_create(1);
            umem_configure(xsks[i].umem_info);
        }

        ret = xsk_configure(&xsks[i], opt_ifname);
        if (ret) {
            dlog_error2("xsk_configure", ret);
            goto cleanup;
        }

        if (opt_shared_umem > 1) {
            if (nbqueues == 1) {
                if (i == 0) {
                    ret = fq_ring_configure(&xsks[i]);
                    if (ret) {
                        dlog_error2("fq_ring_configure", ret);
                        goto cleanup;
                    }
                }
            } else {
                ret = fq_ring_configure(&xsks[i]);
                if (ret) {
                    dlog_error2("fq_ring_configure", ret);
                    goto cleanup;
                }
            }
        } else {
            ret = fq_ring_configure(&xsks[i]);
            if (ret) {
                dlog_error2("fq_ring_configure", ret);
                goto cleanup;
            }
        }

        u32 sockfd = xsk_socket__fd(xsks[i].socket);
        u32 mapkey = nbqueues == 1 && opt_shared_umem > 1 ? xsks[i].index
                                                          : xsks[i].queue_id;
        ret = bpf_map_update_elem(mapfd, &mapkey, &sockfd, BPF_ANY);
        if (ret) {
            dlog_error2("bpf_map_update_elem", ret);
            goto cleanup;
        }

        if (i == 0) {
            socklen = sizeof(struct xdp_options);
            ret = getsockopt(xsk_socket__fd(xsks[i].socket), SOL_XDP,
                XDP_OPTIONS, &xdp_opts, &socklen);
            if (ret) {
                dlog_error2("getsockopt(XDP_OPTIONS)", ret);
            } else if (xdp_opts.flags & XDP_OPTIONS_ZEROCOPY) {
                dlog_info("Zero copy is activated!");
            } else {
                dlog_info("Zero copy is NOT activated!");
            }
        }

        if (IS_THREADED(opt_pollmode, nbqueues)) {
            pthread_attr_t* attrs = opt_affinity ? &xsk_worker_attrs[i] : NULL;
            struct rx_ctx* ctx = &ctxs[i];
            ctx->xsks = &xsks[i];
            ctx->pollmode = opt_pollmode;
            ctx->count = 1;
            ctx->shared_umem = opt_shared_umem;

            if (opt_affinity) {
                pthread_attr_init(attrs);
                // Set process and interrupt affinity to same CPU
                int cpu = i % nprocs;
                nic_set_irq_affinity(opt_irqs[i], cpu);
                CPU_ZERO(&cpusets[i]);
                CPU_SET(cpu, &cpusets[i]);
                ret = pthread_attr_setaffinity_np(attrs, sizeof(cpu_set_t), &cpusets[i]);
                if (ret) {
                    dlog_error2("pthread_attr_setaffinity_np", ret);
                }
            }

            pthread_create(&xsk_workers[i], attrs, poll_rx, (void*)ctx);
        }
    }

    if (!IS_THREADED(opt_pollmode, nbqueues)) {
        struct rx_ctx ctx = {
            .xsks = xsks,
            .pollmode = opt_pollmode,
            .count = nbxsks,
            .shared_umem = opt_shared_umem,
        };

        poll_rx(&ctx);
    }

    struct xsk_stat avg_stats;
    memset(&avg_stats, 0, sizeof(avg_stats));
    for (u32 i = 0; i < nbxsks; i++) {
        if (IS_THREADED(opt_pollmode, nbqueues)) {
            pthread_join(xsk_workers[i], NULL);
        }

        xsk_stats_dump(&xsks[i]);
        avg_stats.runtime = MAX(avg_stats.runtime, xsks[i].stats.runtime);
        avg_stats.fail_polls += xsks[i].stats.fail_polls;
        avg_stats.invalid_ip_pkts += xsks[i].stats.invalid_ip_pkts;
        avg_stats.invalid_udp_pkts += xsks[i].stats.invalid_udp_pkts;
        avg_stats.rcvd_frames += xsks[i].stats.rcvd_frames;
        avg_stats.rcvd_pkts += xsks[i].stats.rcvd_pkts;
        avg_stats.rx_empty_polls += xsks[i].stats.rx_empty_polls;
        avg_stats.rx_fill_fail_polls += xsks[i].stats.rx_fill_fail_polls;
        avg_stats.timeout_polls += xsks[i].stats.timeout_polls;
        avg_stats.xstats.rx_dropped += xsks[i].stats.xstats.rx_dropped;
        avg_stats.xstats.rx_invalid_descs += xsks[i].stats.xstats.rx_invalid_descs;
        avg_stats.xstats.tx_invalid_descs += xsks[i].stats.xstats.tx_invalid_descs;
        avg_stats.xstats.rx_ring_full += xsks[i].stats.xstats.rx_ring_full;
        avg_stats.xstats.rx_fill_ring_empty_descs += xsks[i].stats.xstats.rx_fill_ring_empty_descs;
        avg_stats.xstats.tx_ring_empty_descs += xsks[i].stats.xstats.tx_ring_empty_descs;
    }
    after_interrupts = nic_get_interrupts(opt_ifname, nprocs);

    if (nbxsks != 1) {
        printf("Average Stats:\n");
        stats_dump(&avg_stats);
    }

    for (u32 i = 0; i < after_interrupts->nbirqs; i++) {
        irq_interrupts_t* intr_before = &before_interrupts->interrupts[i];
        irq_interrupts_t* intr_after = &after_interrupts->interrupts[i];

        if (intr_before->irq != intr_after->irq) {
            dlog_errorv("Incorrect IRQs: %d-%d", intr_before->irq, intr_after->irq);
            continue;
        }

        dlog_infov("IRQ-%d: %d", intr_after->irq, intr_after->interrupts - intr_before->interrupts);
    }
cleanup:
    timer_delete(timer);
    xdp_program__detach(kern_prog, ifindex, opt_mode, 0);
    xdp_program__close(kern_prog);

    if (xsks != NULL) {
        for (size_t i = 0; i < nbxsks; i++) {
            xsk_info xsk = xsks[i];
            xsk_socket__delete(xsk.socket);

            if (xsk.umem_info->nbfqs != 1) {
                free(xsk.fill_ring);
                free(xsk.comp_ring);
            }

            if (!opt_shared_umem && xsk.umem_info != NULL) {
                umem_info_free(xsk.umem_info);
                free(xsk.umem_info);
            }
        }
        free(xsks);

        if (xsk_workers != NULL) {
            free(xsk_workers);
        }
    }

    if (xsk_worker_attrs != NULL) {
        for (size_t i = 0; i < nbxsks; i++) {
            pthread_attr_destroy(&xsk_worker_attrs[i]);
        }

        free(xsk_worker_attrs);
    }

    if (ctxs != NULL) {
        free(ctxs);
    }

    if (cpusets != NULL) {
        free(cpusets);
    }

    if (opt_shared_umem) {
        umem_info_free(shared_umem);

        if (shared_umem != NULL) {
            free(shared_umem);
        }
    }
#ifdef NO_HGPG
    set_hugepages(0);
#endif
}
