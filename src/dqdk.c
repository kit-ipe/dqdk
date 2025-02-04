// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// #define USE_SIMD

#include <arpa/inet.h>
#include <linux/bpf.h>
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
#include <endian.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <string.h>
#include <numaif.h>
#include <arpa/inet.h>
#include <math.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <linux/net_tstamp.h>

#define BPF_F_XDP_DEV_BOUND_ONLY (1U << 6)

#include "dqdk-controller.h"
#include "bpf/forwarder.skel.h"
#include "dqdk-blk.h"
#include "dqdk-sys.h"
#include "tcpip/ipv4.h"
#include "tcpip/udp.h"
#include "dqdk.h"
#include "tristan.h"

#define UMEM_FACTOR 64
#define UMEM_LEN (XSK_RING_PROD__DEFAULT_NUM_DESCS * UMEM_FACTOR)
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE

#define UMEM_SIZE (UMEM_LEN * FRAME_SIZE)
#define FILLQ_LEN UMEM_LEN
#define COMPQ_LEN XSK_RING_PROD__DEFAULT_NUM_DESCS

#define UMEM_FLAGS_USE_HGPG (1 << 0)
#define UMEM_FLAGS_UNALIGNED (1 << 1)

volatile u32 break_flag = 0;

static void* umem_buffer_create(u32 size, u8 flags, int driver_numa)
{
    void* mem = NULL;
    if (flags & UMEM_FLAGS_USE_HGPG)
        mem = huge_malloc(driver_numa, size, HUGE_PAGE_2MB);
    else
        mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mlock(mem, size) < 0) {
        munmap(mem, size);
        mem = NULL;
    }

    return mem;
}

static umem_info_t* umem_info_create(u32 size, u8 flags, int driver_numa)
{
    umem_info_t* info = (umem_info_t*)calloc(1, sizeof(umem_info_t));

    info->size = size;
    info->buffer = umem_buffer_create(info->size, flags, driver_numa);
    if (info->buffer == NULL) {
        dlog_error2("umem_buffer_create", 0);
        free(info);
        return NULL;
    }

    info->umem = NULL;
    info->flags = flags;
    return info;
}

static void umem_info_free(umem_info_t* info)
{
    if (info != NULL) {
        munmap(info->buffer, info->size);
        xsk_umem__delete(info->umem);
    }
}

static int umem_configure(umem_info_t* umem)
{
    int ret;

    if (umem == NULL) {
        dlog_error("Invalid umem buffer: NULL");
        return EINVAL;
    }

    const struct xsk_umem_config cfg = {
        .fill_size = FILLQ_LEN,
        .comp_size = COMPQ_LEN,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = umem->flags & UMEM_FLAGS_UNALIGNED ? XDP_UMEM_UNALIGNED_CHUNK_FLAG : 0
    };

    ret = xsk_umem__create(&umem->umem, umem->buffer, umem->size,
        &umem->fq0, &umem->cq0, &cfg);
    if (ret) {
        dlog_error2("xsk_umem__create", ret);
        return ret;
    }

    return 0;
}

static int fq_ring_configure(struct xsk_ring_prod* fq)
{
    // push all frames to fill ring
    u32 idx = 0, ret, fqlen = FILLQ_LEN;

    ret = xsk_ring_prod__reserve(fq, fqlen, &idx);
    if (ret != fqlen) {
        dlog_error2("xsk_ring_prod__reserve", ret);
        return EIO;
    }

    // fill addresses
    for (u32 i = 0; i < fqlen; i++) {
        *xsk_ring_prod__fill_addr(fq, idx++) = (i * FRAME_SIZE);
    }

    xsk_ring_prod__submit(fq, fqlen);
    return 0;
}

static int xsk_configure(dqdk_ctx_t* ctx, dqdk_worker_t* xsk)
{
    int ret = 0;
    const struct xsk_socket_config xsk_config = {
        .rx_size = FILLQ_LEN,
        .tx_size = COMPQ_LEN,
        .bind_flags = ctx->bind_flags,
        .libbpf_flags = ctx->libbpf_flags,
        .xdp_flags = ctx->xdp_flags
    };

    struct xsk_ring_prod* fq = &xsk->umem_info->fq0;
    struct xsk_ring_cons* cq = &xsk->umem_info->cq0;

    ret = fq_ring_configure(fq);
    if (ret) {
        dlog_error2("fq_ring_configure", ret);
        return ret;
    }

    ret = xsk_socket__create_shared(&xsk->socket, ctx->ifname, xsk->queue_id,
        xsk->umem_info->umem, &xsk->rx, &xsk->tx, fq, cq, &xsk_config);
    if (ret) {
        dlog_error2("xsk_socket__create_shared", ret);
        return ret;
    }

    if (ctx->busy_poll) {
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

        sockopt = ctx->batch_size;
        ret = setsockopt(xsk_socket__fd(xsk->socket), SOL_SOCKET, SO_BUSY_POLL_BUDGET,
            (void*)&sockopt, sizeof(sockopt));
        if (ret) {
            dlog_error2("setsockopt(SO_BUSY_POLL_BUDGET)", ret);
            return ret;
        }
    }

    return 0;
}

dqdk_always_inline u8* get_udp_payload(dqdk_worker_t* xsk, u8* buffer, u32 len, u32* datalen)
{
    struct iphdr* packet = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    ++xsk->stats.rcvd_pkts;

    if (dqdk_unlikely(!ip4_audit(packet, len - sizeof(struct ethhdr)))) {
        ++xsk->stats.invalid_ip_pkts;
        return NULL;
    }

    u32 iphdrsz = ip4_get_header_size(packet);
    u32 udplen = ntohs(packet->tot_len) - iphdrsz;
    struct udphdr* udp = (struct udphdr*)(((u8*)packet) + iphdrsz);

    if (dqdk_unlikely(!udp_audit(udp, packet->saddr, packet->daddr, udplen))) {
        xsk->stats.invalid_udp_pkts++;
        return NULL;
    }

    *datalen = udplen - sizeof(struct udphdr);
    return (u8*)(udp + 1);
}

static dqdk_always_inline u8* prefetch_frame(dqdk_worker_t* xsk, int idx)
{
    u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx)->addr;
    u8* frame = xsk_umem__get_data(xsk->umem_info->buffer, addr);
    dqdk_prefetch(frame);

    return frame;
}

#define WORKER_LATENCY(worker, param, latency)                                                                                  \
    do {                                                                                                                        \
        (worker)->stats.param.sum += (latency);                                                                                 \
        (worker)->stats.param.max = MAX((worker)->stats.param.max, (latency));                                                  \
        if ((latency) > 0)                                                                                                      \
            (worker)->stats.param.min = (worker)->stats.param.min == 0 ? (latency) : MIN((worker)->stats.param.min, (latency)); \
        if ((worker)->debug_flags & DQDK_DEBUG_LATENCYDUMP)                                                                     \
            (worker)->stats.param.raw[(worker)->stats.param.raw_idx++] = latency;                                               \
    } while (0)

static dqdk_always_inline void process_frame(dqdk_worker_t* xsk, u8* frame, u32 len)
{
    u32 datalen = 0;

    tristan_private_t* private = (tristan_private_t*)xsk->private;

    if (dqdk_unlikely(private->mode == TRISTAN_MODE_DROP))
        return;

    u8* data = get_udp_payload(xsk, frame, len, &datalen);

    if (xsk->debug_flags && xsk->soft_timestamp != BAD_CLOCK) {
        u64 t0 = *((u64*)frame); // Get hardware timestamp
        s64 latency = xsk->soft_timestamp - t0;
        WORKER_LATENCY(xsk, queuing_latency, latency);
    }

    if (dqdk_unlikely(datalen == 0 || data == NULL))
        return;

    if (private->mode == TRISTAN_MODE_WAVEFORM)
        tristan_daq_waveform(private, xsk, data, datalen);
    else if (private->mode == TRISTAN_MODE_ENERGYHISTO)
        tristan_daq_energyhisto(private, xsk, data, datalen);
}

static dqdk_always_inline int do_daq(dqdk_worker_t* xsk)
{
    umem_info_t* umem = xsk->umem_info;
    u32 idx_rx = 0, idx_fq = 0;
    struct xsk_ring_prod* fq = &umem->fq0;

    if (xsk->debug_flags)
        xsk->soft_timestamp = clock_nsecs_real();

    int rcvd = xsk_ring_cons__peek(&xsk->rx, xsk->batch_size, &idx_rx);
    if (dqdk_unlikely(!rcvd)) {
        /**
         * wakeup by issuing a recvfrom if needs wakeup
         * or if busy poll was specified. If SO_PREFER_BUSY_POLL is specified
         * then we should wake up to force a bottom-half interrup
         */
        if (xsk->busy_poll || xsk_ring_prod__needs_wakeup(fq)) {
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

        if (xsk->busy_poll || xsk_ring_prod__needs_wakeup(fq)) {
            xsk->stats.rx_fill_fail_polls++;
            recvfrom(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }

        ret = xsk_ring_prod__reserve(fq, rcvd, &idx_fq);
    }

    ++xsk->stats.rx_successful_fills;

    for (int i = 0; i < rcvd; i++) {
        if (i != rcvd - 1)
            prefetch_frame(xsk, idx_rx + 1);

        const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
        u8* frame = xsk_umem__get_data(xsk->umem_info->buffer, desc->addr);

        process_frame(xsk, frame, desc->len);

        *xsk_ring_prod__fill_addr(fq, idx_fq++) = desc->addr;
    }

    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk_ring_prod__submit(fq, rcvd);

    xsk->stats.rcvd_frames += rcvd;

    if (xsk->debug_flags && xsk->soft_timestamp != BAD_CLOCK) {
        u64 postproc_ts = clock_nsecs_real();
        if (postproc_ts != BAD_CLOCK) {
            s64 latency = postproc_ts - xsk->soft_timestamp;
            s64 thrsld = 5000000;
            if (xsk->stats.rcvd_frames == 6500000) {
                clock_nsleep(thrsld - latency);
                postproc_ts = clock_nsecs_real();
                latency = postproc_ts - xsk->soft_timestamp;
            }
            WORKER_LATENCY(xsk, processing_latency, latency);
        }
    }

    return 0;
}

static int run_daq(dqdk_worker_t* xsk)
{
    u64 t0, t1;

    t0 = clock_nsecs_mono();
    while (dqdk_unlikely(!break_flag)) {
        do_daq(xsk);
    }
    t1 = clock_nsecs_mono();

    socklen_t socklen = sizeof(struct xdp_statistics);
    xsk->stats.runtime = t1 - t0;
    int ret = getsockopt(xsk_socket__fd(xsk->socket), SOL_XDP,
        XDP_STATISTICS, &(xsk->stats.xstats), &socklen);
    if (ret) {
        dlog_error2("getsockopt(XDP_STATISTICS)", ret);
    }

    return 0;
}

static void signal_handler(int sig)
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

#define AVG_PPS(pkts, rt) (((rt) == 0) ? 0 : (pkts) * 1e9 / (rt))

static void stats_dump(dqdk_stats_t* stats, u8 debug)
{
    printf("    Total runtime (ns):       %llu\n", stats->runtime);
    printf("    Received Frames:          %llu\n", stats->rcvd_frames);
    printf("    Received Packets:         %llu\n", stats->rcvd_pkts);
    printf("    Invalid L3 Packets:       %llu\n", stats->invalid_ip_pkts);
    printf("    Invalid L4 Packets:       %llu\n", stats->invalid_udp_pkts);
    printf("    Failed Polls:             %llu\n", stats->fail_polls);
    printf("    Timeout Polls:            %llu\n", stats->timeout_polls);
    printf("    XSK Fill Fail Polls:      %llu\n", stats->rx_fill_fail_polls);
    printf("    XSK RX Successful Fills:  %llu\n", stats->rx_successful_fills);
    printf("    XSK RXQ Empty:            %llu\n", stats->rx_empty_polls);
    printf("    X-XSK RX Dropped:         %llu\n", stats->xstats.rx_dropped);
    printf("    X-XSK RX FillQ Empty:     %llu\n", stats->xstats.rx_fill_ring_empty_descs);
    printf("    X-XSK RX Invalid Descs:   %llu\n", stats->xstats.rx_invalid_descs);
    printf("    X-XSK RX Ring Full:       %llu\n", stats->xstats.rx_ring_full);
    if (debug) {
        printf("    Queuing Latency:          AVG=%fns    MIN=%lldns    MAX=%lldns\n",
            AVG(stats->queuing_latency.sum, stats->rcvd_frames), stats->queuing_latency.min, stats->queuing_latency.max);
        printf("    Processing Latency:       AVG=%fns    MIN=%lldns    MAX=%lldns\n",
            AVG(stats->processing_latency.sum, stats->rcvd_frames), stats->processing_latency.min, stats->processing_latency.max);
    }
}

static void xsk_stats_dump(dqdk_worker_t* xsk)
{
    printf("XSK %u on Queue %u Statistics:\n", xsk->index, xsk->queue_id);
    stats_dump(&xsk->stats, xsk->debug_flags & DQDK_DEBUG);
}

void dqdk_usage(char** argv)
{
    printf("Usage: %s -i <interface_name> -q <hardware_queue_id>\n", argv[0]);
    printf("Arguments:\n");
    printf("    -a <ports-range>             Accept source ports range e.g. 5000-5002 will reject all ports 3 ports 5000, 5001 & 5002,\n");
    printf("    -d <duration>                Set the run duration in seconds. Required for TRISTAN waveform and listwave modes\n");
    printf("    -i <interface>               Set NIC to work on\n");
    printf("    -q <qid[-qid]>               Set range of hardware queues to work on e.g. -q 1 or -q 1-3.\n");
    printf("                                 Specifying multiple queues will launch a thread for each queue except if -p poll\n");
    printf("    -v                           Verbose\n");
    printf("    -b <size>                    Set batch size. Default: 64\n");
    printf("    -w                           Use XDP need wakeup flag\n");
    printf("    -s                           Expected Packet Size. Default: 3392\n");
    printf("    -l                           Dump latency values as a CSV file. Requires -D\n");
    printf("    -m <waveform|energy-histo>   Set TRISTAN Mode.\n");
    printf("    -A <irq1,irq2,...>           Set affinity mapping between application threads and drivers queues\n");
    printf("                                 e.g. q1 to irq1, q2 to irq2,...\n");
    printf("    -B                           Enable NAPI busy-poll\n");
    printf("    -H                           Considering Hyper-threading is enabled, this flag will assign affinity\n");
    printf("                                 of softirq and the app to two logical cores of the same physical core.\n");
    printf("    -G                           Activate Huge Pages for UMEM allocation\n");
    printf("    -S                           Run IRQ and App on same core\n");
    printf("    -D                           Enable Latency measurements\n");
}

#define dqdk_update_mask(mask, howmany) (*mask = *mask & (0xffffffffffffffff << (howmany)));

int dqdk_get_next_core(unsigned long* mask)
{
    int ret = ffsll(*mask);
    dqdk_update_mask(mask, ret);
    return ret - 1;
}

u32 dqdk_calc_affinity(int irq, int ht, int samecore, unsigned long* cpumask)
{
    u32 affinity = 0;
    u16 app_aff = 0, irq_aff = dqdk_get_next_core(cpumask);
    int smt = is_smt();

    if (ht) {
        if (!smt) {
            dlog_error("Hyper-Threading is not enabled but is chosen in the configuration");
            return (u32)-1;
        }
        app_aff = samecore ? irq_aff : cpu_smt_sibling(irq_aff);
    } else {
        if (samecore) {
            app_aff = irq_aff;
        } else {
            app_aff = irq_aff + 1;
            dqdk_update_mask(cpumask, app_aff + 1);
        }
    }
    dlog_infov("IRQ(%d) Affinity=%d and Thread Afinity=%d", irq, irq_aff, app_aff);
    affinity = ((irq_aff << 16) & 0xffff0000) | (app_aff & 0x0000ffff);
    return affinity;
}

#define DQDK_APP_AFFINITY(x) ((u16)(x & 0x0000ffff))
#define DQDK_IRQ_AFFINITY(x) ((u16)(x >> 16) & 0x0000ffff)

int dqdk_set_affinity(int ht, int samecore, int irq, unsigned long* cpumask, cpu_set_t* cpuset, pthread_attr_t* attrs)
{
    u32 affinity = dqdk_calc_affinity(irq, ht, samecore, cpumask);
    int ret = 0;

    if (affinity == (u32)-1) {
        return -1;
    }

    nic_set_irq_affinity(irq, DQDK_IRQ_AFFINITY(affinity));

    CPU_ZERO(cpuset);
    CPU_SET(DQDK_APP_AFFINITY(affinity), cpuset);
    if (attrs) {
        ret = pthread_attr_setaffinity_np(attrs, sizeof(cpu_set_t), cpuset);
        pthread_attr_setschedpolicy(attrs, SCHED_FIFO);
        struct sched_param schedparam = { .sched_priority = sched_get_priority_max(SCHED_FIFO) };
        pthread_attr_setschedparam(attrs, &schedparam);
        if (ret) {
            dlog_error2("pthread_attr_setaffinity_np", ret);
        }
        return ret;
    }

    return sched_setaffinity(0, sizeof(cpu_set_t), cpuset);
}

unsigned long long int dqdk_round_to_power2(unsigned long long int n)
{
    if (n == 0)
        return 1;

    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n++;

    return n;
}

struct worker_obj {
    dqdk_worker_t* xsk;
    dqdk_ctx_t* ctx;
};

static void dqdk_worker_free(dqdk_worker_t* xsk)
{
    if (xsk) {
        if (xsk->thread_attrs) {
            pthread_attr_destroy(xsk->thread_attrs);
            free(xsk->thread_attrs);
        }

        xsk_socket__delete(xsk->socket);
        if (xsk->umem_info != NULL) {
            umem_info_free(xsk->umem_info);
            free(xsk->umem_info);
        }

        if (xsk->stats.queuing_latency.raw != NULL)
            free(xsk->stats.queuing_latency.raw);

        if (xsk->stats.processing_latency.raw != NULL)
            free(xsk->stats.processing_latency.raw);

        free(xsk);
    }
}

static void* dqdk_worker(void* ptr)
{
    int ret = 0;
    struct worker_obj* wobj = (struct worker_obj*)ptr;
    dqdk_worker_t* xsk = wobj->xsk;
    dqdk_ctx_t* ctx = wobj->ctx;

    xsk->umem_info = umem_info_create(ctx->umem_size, ctx->umem_flags, ctx->numa_node);
    if (xsk->umem_info == NULL) {
        dlog_error("Error allocating umem");
        goto error;
    }

    ret = umem_configure(xsk->umem_info);
    if (ret)
        goto error;

    ret = xsk_configure(ctx, xsk);
    if (ret) {
        dlog_error2("xsk_configure", ret);
        goto error;
    }

    u32 sockfd = xsk_socket__fd(xsk->socket);
    u32 mapkey = xsk->queue_id;
    ret = bpf_map__update_elem(ctx->forwarder->maps.xsks_map, &mapkey, sizeof(u32), &sockfd, sizeof(u32), BPF_ANY);
    if (ret) {
        dlog_error2("bpf_map__update_elem", ret);
        goto error;
    }

    if (xsk->index == 0) {
        struct xdp_options xdp_opts;
        socklen_t socklen = sizeof(xdp_opts);
        ret = getsockopt(xsk_socket__fd(xsk->socket), SOL_XDP,
            XDP_OPTIONS, &xdp_opts, &socklen);
        if (ret) {
            dlog_error2("getsockopt(XDP_OPTIONS)", ret);
        } else if (xdp_opts.flags & XDP_OPTIONS_ZEROCOPY) {
            dlog_info("Zero copy is activated!");
        } else {
            dlog_info("Zero copy is NOT activated!");
        }
    }

    if (!ctx->barrier_init || (ret = pthread_barrier_wait(&ctx->barrier)) > 0) {
        dlog_error2("pthread_barrier_wait", ret);
        goto error;
    }

    ret = run_daq(xsk);
    goto cleanup;

error:
    dlog_errorv("Worker %d is dead!", xsk->index);
    if (!ctx->barrier_init || (ret = pthread_barrier_wait(&ctx->barrier)) > 0)
        dlog_error2("pthread_barrier_wait", ret);

cleanup:
    free(wobj);
    return NULL;
}

int dqdk_worker_init(dqdk_ctx_t* ctx, int qid, int irq, void* noshared_private)
{
    static int worker_index = 0;
    int ret;

    dqdk_worker_t* xsk = calloc(1, sizeof(dqdk_worker_t));
    ctx->workers[worker_index] = xsk;

    struct worker_obj* wobj = calloc(1, sizeof(struct worker_obj));
    wobj->ctx = ctx;
    wobj->xsk = xsk;

    xsk->queue_id = qid;
    xsk->index = worker_index++;
    xsk->private = ctx->private;
    xsk->dedicated_private = noshared_private;
    xsk->batch_size = ctx->batch_size;
    xsk->busy_poll = ctx->busy_poll;
    xsk->debug_flags = ctx->debug_flags;
    xsk->thread_attrs = calloc(1, sizeof(pthread_attr_t));

    if (xsk->debug_flags & DQDK_DEBUG_LATENCYDUMP) {
        xsk->stats.queuing_latency.raw = calloc(DQDK_MAX_LATENCY_METRICS, sizeof(s64));
        xsk->stats.processing_latency.raw = calloc(DQDK_MAX_LATENCY_METRICS, sizeof(s64));
    }

    pthread_attr_init(xsk->thread_attrs);
    ret = dqdk_set_affinity(ctx->hyperthreading, ctx->samecore, irq, &ctx->cpu_mask, &xsk->cset, xsk->thread_attrs);
    if (ret)
        return -1;

    return pthread_create(&xsk->thread, xsk->thread_attrs, dqdk_worker, (void*)wobj);
}

static int dqdk_ctx_free(dqdk_ctx_t* ctx)
{
    if (ctx == NULL)
        return -1;

    if (ctx->ifname != NULL)
        free(ctx->ifname);

    if (ctx->forwarder != NULL) {
        LIBBPF_OPTS(bpf_xdp_attach_opts, opts, .old_prog_fd = bpf_program__fd(ctx->forwarder->progs.dqdk_forwarder));
        int ret = bpf_xdp_detach(ctx->ifindex, XDP_FLAGS_DRV_MODE, &opts);
        if (ret < 0)
            dlog_error2("bpf_xdp_detach", ret);
        forwarder__destroy(ctx->forwarder);
    }

    if (ctx->workers != NULL)
        free(ctx->workers);

    if (ctx->barrier_init)
        pthread_barrier_destroy(&ctx->barrier);

    set_hugepages(ctx->numa_node, 0, HUGE_PAGE_2MB);
    set_hugepages(ctx->numa_node, 0, HUGE_PAGE_1GB);

    free(ctx);
    return 0;
}

int dqdk_waitall(dqdk_ctx_t* ctx)
{
    dqdk_worker_t* worker;
    break_flag = 1;

    if (!ctx)
        return -1;

    if (ctx->status > DQDK_STATUS_NONE) {
        for (u32 _i = 0; _i < ctx->nbqueues; _i++) {
            worker = ctx->workers[_i];
            if (worker)
                pthread_join(worker->thread, NULL);
        }
    }

    return 0;
}

static int dqdk_ctx_enable_hwtstamp(dqdk_ctx_t* ctx)
{
    struct hwtstamp_config config;
    int ret = 0;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ctx->ifname, IFNAMSIZ);

    config.flags = 0;
    config.tx_type = HWTSTAMP_TX_OFF;
    config.rx_filter = HWTSTAMP_FILTER_ALL;

    ifr.ifr_data = (void*)&config;

    if (ioctl(sock, SIOCSHWTSTAMP, &ifr) < 0) {
        ret = -1;
        goto exit;
    }

    close(sock);
exit:
    return ret;
}

dqdk_ctx_t* dqdk_ctx_init(char* ifname, u32 queues[], u32 nbqueues, u8 umem_flags, u64 umem_size, u32 batch_size, u8 needs_wakeup, u8 busypoll, enum xdp_attach_mode xdp_mode, u32 nbirqs, u8 irqworker_samecore, u32 packetsz, u8 debug, u8 hyperthreading, void* sharedprivate)
{
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    dqdk_ctx_t* ctx = calloc(1, sizeof(dqdk_ctx_t));
    int ret = 0;
    u32 nprocs;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGUSR1, signal_handler);

    if (ifname == NULL || nbqueues == 0) {
        dlog_error("Invalid interface name or number of queues");
        dqdk_ctx_free(ctx);
        return NULL;
    }

    ctx->ifname = strdup(ifname);
    ctx->ifindex = if_nametoindex(ifname);
    memcpy(&ctx->queues, queues, sizeof(ctx->queues));

    if (ctx->ifindex < 0) {
        dlog_error("Invalid NIC index\n");
        dqdk_ctx_free(ctx);
        return NULL;
    }

    ctx->workers = calloc(nbqueues, sizeof(dqdk_worker_t*));
    ctx->nbports = 0;
    ctx->cpu_mask = 0;
    ctx->xmode = xdp_mode;
    ctx->batch_size = batch_size;
    ctx->needs_wakeup = needs_wakeup;
    ctx->busy_poll = busypoll;
    ctx->nbqueues = nbqueues;
    ctx->private = sharedprivate;
    ctx->hyperthreading = hyperthreading;
    ctx->debug_flags = debug;
    ctx->packetsz = packetsz;
    ctx->ifspeed = dqdk_get_link_speed(ctx->ifname);
    ctx->umem_flags = umem_flags;
    ctx->umem_size = umem_size;
    ctx->libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
    ctx->bind_flags = (ctx->needs_wakeup ? XDP_USE_NEED_WAKEUP : 0) | (xdp_mode == XDP_MODE_SKB ? XDP_COPY : 0);
    ctx->xdp_flags = 0;
    ctx->status = DQDK_STATUS_NONE;

    dlog_infov("Selected Interface (%s) Speed=%dMbps", ctx->ifname, ctx->ifspeed);

    ctx->numa_node = nic_numa_node(ifname);
    int is_numa = numa_available();
    if (is_numa < 0) {
        nprocs = get_nprocs();
    } else {
        dlog_infov("NUMA is detected! %s is owned by node %d", ctx->ifname, ctx->numa_node);

        // failure to get numa node or PCI is equidistant to all NUMA nodes => assign node0
        if (ctx->numa_node == -1)
            ctx->numa_node = 0;

        dlog_infov("Selected NUMA node is %d", ctx->numa_node);

        numa_set_bind_policy(1);
        struct bitmask* nodemask = numa_allocate_nodemask();
        struct bitmask* fromnodemask = numa_allocate_nodemask();

        numa_bitmask_clearall(nodemask);
        numa_bitmask_setbit(nodemask, ctx->numa_node);
        numa_bind(nodemask);

        numa_bitmask_setall(fromnodemask);
        numa_bitmask_clearbit(fromnodemask, ctx->numa_node);
        numa_migrate_pages(getpid(), fromnodemask, nodemask);

        numa_free_nodemask(fromnodemask);
        numa_free_nodemask(nodemask);

        struct bitmask* cpumask = numa_allocate_cpumask();
        numa_node_to_cpus(ctx->numa_node, cpumask);
        ctx->cpu_mask = *cpumask->maskp;
        numa_free_cpumask(cpumask);
        nprocs = popcountl(ctx->cpu_mask);
        dlog_infov("NUMA CPU Mask is %#010lX of %d CPUs", ctx->cpu_mask, nprocs);
    }

    if ((ctx->debug_flags & DQDK_DEBUG_LATENCYDUMP) && ~(ctx->debug_flags & DQDK_DEBUG) > 0) {
        dlog_error("Dumping latency measurements requires debug mode");
        dqdk_ctx_free(ctx);
        return NULL;
    }

    if (ctx->umem_flags & UMEM_FLAGS_USE_HGPG) {
        int additional_pages = HUGETLB_CALC_2MB(ctx->umem_size * ctx->nbqueues);
        int needed_hgpg = get_hugepages(ctx->numa_node, HUGE_PAGE_2MB) + additional_pages;
        set_hugepages(ctx->numa_node, needed_hgpg, HUGE_PAGE_2MB);
        dlog_infov("Huge pages are activated! Allocated 2MB pages=%d", needed_hgpg);
    }

    if (nbirqs != nbqueues) {
        dlog_errorv("IRQs=%d and number of queues=%d must be equal. Make sure you pass the correct arguments to -A", nbirqs, nbqueues);
        dqdk_ctx_free(ctx);
        return NULL;
    }

    if (!irqworker_samecore && nbqueues * 2 > nprocs) {
        dlog_errorv("IRQs and Application threads are running on different cores. You should have enough dedicated cores for both of them. The maximum possible cores now is %d", nprocs);
        dqdk_ctx_free(ctx);
        return NULL;
    }

    if (ctx->debug_flags) {
        libbpf_set_print(infoprint);
        if (dqdk_ctx_enable_hwtstamp(ctx) < 0) {
            dlog_error2("dqdk_ctx_enable_hwtstamp", -1);
            dqdk_ctx_free(ctx);
            return NULL;
        }
    }

    char buffer[1024] = { 0 };
    char* queues_format = buffer;
    for (u32 i = 0; i < nbqueues; i++) {
        ret = snprintf(queues_format, (i == nbqueues - 1) ? 2 : 4, (i == nbqueues - 1) ? "%d" : "%d, ", ctx->queues[i]);
        queues_format += ret;
    }

    dlog_infov("DQDK %d NIC queues: %s", nbqueues, buffer);
    if ((ret = setrlimit(RLIMIT_MEMLOCK, &rlim))) {
        dlog_error2("setrlimit", ret);
        dqdk_ctx_free(ctx);
        return NULL;
    }

    ctx->forwarder = forwarder__open();
    ctx->forwarder->bss->debug = debug;

    bpf_program__set_ifindex(ctx->forwarder->progs.dqdk_forwarder, ctx->ifindex);
    bpf_program__set_flags(ctx->forwarder->progs.dqdk_forwarder, BPF_F_XDP_DEV_BOUND_ONLY);
    bpf_program__set_type(ctx->forwarder->progs.dqdk_forwarder, BPF_PROG_TYPE_XDP);
    ret = forwarder__load(ctx->forwarder);
    if (ret < 0) {
        dlog_error2("forwarder__load", ret);
        dqdk_ctx_free(ctx);
        return NULL;
    }

    LIBBPF_OPTS(bpf_xdp_attach_opts, opts, .old_prog_fd = -1);
    ret = bpf_xdp_attach(ctx->ifindex, bpf_program__fd(ctx->forwarder->progs.dqdk_forwarder), XDP_FLAGS_DRV_MODE, &opts);
    if (ret < 0) {
        dlog_error2("bpf_xdp_attach", ret);
        dqdk_ctx_free(ctx);
        return NULL;
    }

    ret = pthread_barrier_init(&ctx->barrier, NULL, nbqueues + 1);
    if (ret) {
        dlog_error2("pthread_barrier_init", ret);
        dqdk_ctx_free(ctx);
        return NULL;
    }
    ctx->barrier_init = true;
    ctx->status = DQDK_STATUS_STARTED;

    return ctx;
}

int dqdk_add_port(dqdk_ctx_t* ctx, u16 port)
{
    if (bpf_map__update_elem(ctx->forwarder->maps.accept_ports, &port, sizeof(port), &port, sizeof(port), 0) < 0) {
        dlog_errorv("Error adding port %u to accept-ports: %s(%d)", port, strerror(errno), errno);
        return -1;
    }

    ctx->nbports++;
    return 0;
}

int dqdk_start(dqdk_ctx_t* ctx)
{
    if (!ctx)
        return -1;

    if (ctx->nbports == 0) {
        dlog_error("Please provide a range of source ports to accept data on");
        return -1;
    }

    if (!ctx->barrier_init || pthread_barrier_wait(&ctx->barrier) > 0)
        return -1;

    ctx->status = DQDK_STATUS_READY;

    return 0;
}

u8* dqdk_huge_malloc(dqdk_ctx_t* ctx, u64 size, huge_page_size_t pagesz)
{
    int additional_pages = pagesz == HUGE_PAGE_2MB ? HUGETLB_CALC_2MB(size) : HUGETLB_CALC_1GB(size);
    int needed_hgpg = get_hugepages(ctx->numa_node, pagesz) + additional_pages;
    set_hugepages(ctx->numa_node, needed_hgpg, pagesz);
    u8* mem = huge_malloc(ctx->numa_node, size, pagesz);
    if (!mem)
        goto exit;

    if (mlock(mem, size) < 0) {
        dqdk_huge_free(ctx, mem, size);
        mem = NULL;
    }

exit:
    return mem;
}

int dqdk_huge_free(dqdk_ctx_t* ctx, u8* mem, u64 size)
{
    (void)ctx;
    return munmap(mem, size);
}

static void dqdk_latencystats_dump(dqdk_worker_t* worker, FILE* file)
{
    char buffer[1024] = { 0 };

    for (int i = 0; i < DQDK_MAX_LATENCY_METRICS; i++) {
        memset(buffer, 0, 1024);
        snprintf(buffer, 1024, "%d,Queuing,%lld,%d\n", worker->index, worker->stats.queuing_latency.raw[i], DQDK_MAX_LATENCY_METRICS);
        fwrite(buffer, strlen(buffer), 1, file);

        memset(buffer, 0, 1024);
        snprintf(buffer, 1024, "%d,Processing,%lld,%d\n", worker->index, worker->stats.processing_latency.raw[i], DQDK_MAX_LATENCY_METRICS);
        fwrite(buffer, strlen(buffer), 1, file);
        fflush(file);
    }
}

int dqdk_ctx_fini(dqdk_ctx_t* ctx)
{
    dqdk_worker_t* worker;
    break_flag = 1;

    if (!ctx)
        return -1;

    if (ctx->status > DQDK_STATUS_NONE) {
        FILE* file = NULL;

        if (ctx->debug_flags & DQDK_DEBUG_LATENCYDUMP) {
            file = fopen("latency-stats.csv", "w");
            if (file) {
                char* buffer = "Worker,Type,Value,Count\n";
                fwrite(buffer, strlen(buffer), 1, file);
            }
        }

        for (u32 _i = 0; _i < ctx->nbqueues; _i++) {
            worker = ctx->workers[_i];
            if (worker) {
                if (worker->debug_flags & DQDK_DEBUG_LATENCYDUMP)
                    dqdk_latencystats_dump(worker, file);
                dqdk_worker_free(worker);
                ctx->workers[_i] = NULL;
            }
        }

        if (file)
            fclose(file);
    }

    return dqdk_ctx_free(ctx);
}

void dqdk_dump_stats(dqdk_ctx_t* ctx)
{
    dqdk_worker_t* worker;
    dqdk_stats_t avg_stats;

    if (ctx == NULL)
        return;

    memset(&avg_stats, 0, sizeof(avg_stats));

    for (u32 i = 0; i < ctx->nbqueues; i++) {
        worker = ctx->workers[i];
        xsk_stats_dump(worker);
        avg_stats.runtime = MAX(avg_stats.runtime, worker->stats.runtime);
        avg_stats.rcvd_pkts += worker->stats.rcvd_pkts;
        avg_stats.rcvd_frames += worker->stats.rcvd_frames;

        avg_stats.fail_polls += worker->stats.fail_polls;
        avg_stats.invalid_ip_pkts += worker->stats.invalid_ip_pkts;
        avg_stats.invalid_udp_pkts += worker->stats.invalid_udp_pkts;
        avg_stats.rx_empty_polls += worker->stats.rx_empty_polls;
        avg_stats.rx_fill_fail_polls += worker->stats.rx_fill_fail_polls;
        avg_stats.timeout_polls += worker->stats.timeout_polls;
        avg_stats.rx_successful_fills += worker->stats.rx_successful_fills;

        avg_stats.xstats.rx_dropped += worker->stats.xstats.rx_dropped;
        avg_stats.xstats.rx_invalid_descs += worker->stats.xstats.rx_invalid_descs;
        avg_stats.xstats.rx_ring_full += worker->stats.xstats.rx_ring_full;
        avg_stats.xstats.rx_fill_ring_empty_descs += worker->stats.xstats.rx_fill_ring_empty_descs;

        avg_stats.queuing_latency.sum += worker->stats.queuing_latency.sum;
        avg_stats.queuing_latency.min = avg_stats.queuing_latency.min == 0 ? worker->stats.queuing_latency.min : MIN(avg_stats.queuing_latency.min, worker->stats.queuing_latency.min);
        avg_stats.queuing_latency.max = MAX(avg_stats.queuing_latency.max, worker->stats.queuing_latency.max);

        avg_stats.processing_latency.sum += worker->stats.processing_latency.sum;
        avg_stats.processing_latency.min = avg_stats.processing_latency.min == 0 ? worker->stats.processing_latency.min : MIN(avg_stats.processing_latency.min, worker->stats.processing_latency.min);
        avg_stats.processing_latency.max = MAX(avg_stats.processing_latency.max, worker->stats.processing_latency.max);
    }

    if (ctx->nbqueues != 1) {
        printf("Average Stats:\n");
        stats_dump(&avg_stats, ctx->debug_flags & DQDK_DEBUG);
    }
}

int main(int argc, char** argv)
{
    // options values
    char* opt_ifname = NULL;
    u32 opt_batchsize = 64, opt_queues[MAX_QUEUES], opt_irqs[MAX_QUEUES];
    double opt_duration = -1;
    u8 opt_needs_wakeup = 0, opt_hyperthreading = 0, opt_samecore = 0,
       opt_busy_poll = 0, opt_umem_flags = 0, opt_debug = 0;
    int opt_packetsz = 3438;

    // program variables
    tristan_mode_t mode = TRISTAN_MODE_WAVEFORM;
    tristan_private_t private;
    int opt;
    u32 nbqueues = 0, nbirqs = 0;

    dqdk_ctx_t* ctx = NULL;
    u16 start_port = 0, end_port = 0;
    dqdk_controller_t* controller = NULL;

    if (argc == 1) {
        dqdk_usage(argv);
        return 0;
    }

    memset(&private, 0, sizeof(private));
    memset(opt_queues, -1, sizeof(u32) * MAX_QUEUES);
    memset(opt_irqs, -1, sizeof(u32) * MAX_QUEUES);

    while ((opt = getopt(argc, argv, "a:b:d:hi:q:ws:lm:A:BDHGS")) != -1) {
        switch (opt) {
        case 'h':
            dqdk_usage(argv);
            return 0;
        case 'a':
            char* delimiter = NULL;
            start_port = strtol(optarg, &delimiter, 10);
            if (delimiter != optarg) {
                end_port = strtol(++delimiter, &delimiter, 10);
            } else {
                dlog_error("Invalid port range.");
                exit(EXIT_FAILURE);
            }
            break;
        case 'A':
            // mapping to queues is 1-to-1 e.g. first irq to first queue...
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
                        || (delimiter[0] != ',' && delimiter[0] != 0)) {
                        dlog_error("Invalid IRQ string");
                        goto cleanup;
                    }

                    cursor = delimiter + 1;
                    opt_irqs[nbirqs++] = irq;
                } while (delimiter[0] != 0);
            }
            break;
        case 'd':
            opt_duration = atof(optarg);
            break;
        case 'i':
            opt_ifname = optarg;
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
        case 's':
            opt_packetsz = atoi(optarg);
            break;
        case 'b':
            opt_batchsize = atoi(optarg);
            break;
        case 'w':
            opt_needs_wakeup = 1;
            break;
        case 'B':
            opt_busy_poll = 1;
            break;
        case 'H':
            opt_hyperthreading = 1;
            break;
        case 'G':
            opt_umem_flags |= UMEM_FLAGS_USE_HGPG;
            break;
        case 'S':
            opt_samecore = 1;
            break;
        case 'm':
            if (strcmp(optarg, "drop") == 0) {
                mode = TRISTAN_MODE_DROP;
            } else if (strcmp(optarg, "energy-histo") == 0) {
                mode = TRISTAN_MODE_ENERGYHISTO;
            } else if (strcmp(optarg, "waveform") == 0) {
                mode = TRISTAN_MODE_WAVEFORM;
            } else {
                dlog_errorv("Unknown TRISTAN mode: %s", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'D':
            opt_debug |= DQDK_DEBUG;
            break;
        case 'l':
            opt_debug |= DQDK_DEBUG_LATENCYDUMP;
            break;
        default:
            dqdk_usage(argv);
            dlog_error("Invalid Arg\n");
            exit(EXIT_FAILURE);
        }
    }

    dlog_info("Waiting for Control Software to connect...");
    controller = dqdk_controller_start();
    if (controller == NULL)
        goto cleanup;

    ctx = dqdk_ctx_init(opt_ifname, opt_queues, nbqueues, opt_umem_flags, UMEM_SIZE, opt_batchsize, opt_needs_wakeup, opt_busy_poll, XDP_MODE_NATIVE, nbirqs, opt_samecore, opt_packetsz, opt_debug, opt_hyperthreading, (void*)&private);

    if (!ctx) {
        dlog_info("Error Initializing DQDK Context");
        goto cleanup;
    }

    for (u16 p = start_port; p <= end_port; p++) {
        if (dqdk_add_port(ctx, p) < 0)
            goto cleanup;
    }

    private.mode = mode;
    if (mode != TRISTAN_MODE_DROP) {
        dlog_info("Allocating TRISTAN Memory...");
        if (mode == TRISTAN_MODE_ENERGYHISTO || mode == TRISTAN_MODE_LISTWAVE) {
            private.histo = (tristan_histo_t*)dqdk_huge_malloc(ctx, TRISTAN_HISTO_SZ, HUGE_PAGE_2MB);
            if (private.histo == NULL) {
                dlog_error("Error allocating huge pages memory for TRISTAN histograms");
                goto cleanup;
            }
        }

        if (mode == TRISTAN_MODE_WAVEFORM || mode == TRISTAN_MODE_LISTWAVE) {
            if (opt_duration < 0) {
                dlog_error("TRISTAN Modes: waveform and listwave require setting a duration");
                goto cleanup;
            }

            /* Calculate the size of the needed buffer using link speed, duration and packet size
             * Convert link speed to bytes per second from Mbits per second,
             * Convert duration from milliseconds to seconds
             */
            double bulk_size = ((ctx->ifspeed * 1.0 / 8) * 1024 * 1024) * (opt_duration * 1.0 / 1000);
            private.max_bulk_size = (u64)ceil(bulk_size);
            private.bulk = dqdk_huge_malloc(ctx, private.max_bulk_size, HUGE_PAGE_2MB);
            private.head = private.bulk;
            private.bulk_size = 0;

            if (private.bulk == NULL) {
                dlog_error("Error allocating huge pages memory for TRISTAN memory");
                goto cleanup;
            }
        }
    }

    for (u32 i = 0; i < nbqueues; i++) {
        if (dqdk_worker_init(ctx, opt_queues[i], opt_irqs[i], NULL) < 0)
            goto cleanup;
    }

    if (dqdk_start(ctx) < 0) {
        dlog_error("Error starting DQDK");
        goto cleanup;
    }

    dlog_info("DAQ Started!");

    int ret = dqdk_controller_wait(controller, ctx);
    // FIXME: in case the connection closed we need to run some timer and close after that
    if (ret < 0)
        goto cleanup;

    dlog_info("Closing...");

    if (mode != TRISTAN_MODE_DROP) {
        if (private.histo) {
            dlog_info("Saving TRISTAN Histogram, this may take a while...");
            dqdk_blk_status_t stats = dqdk_blk_dump("tristan-histo.bin", FILE_BSIZE, TRISTAN_HISTO_SZ, private.histo);
            if (stats.status != 0)
                dlog_infov("DQDK-BLK Object dumping failed, returned %d\n", stats.status);
        }

        if (private.bulk && private.head - private.bulk != 0) {
            dlog_info("Saving TRISTAN Waveform, this may take a while...");
            dqdk_blk_status_t stats = dqdk_blk_dump("tristan-raw.bin", FILE_BSIZE, private.head - private.bulk, private.bulk);
            if (stats.status != 0)
                dlog_infov("DQDK-BLK Object dumping failed, returned %d\n", stats.status);
        }
    }

    dqdk_waitall(ctx);
    dqdk_dump_stats(ctx);

cleanup:
    if (dqdk_controller_closed(controller) < 0)
        dlog_error("Error sending closed status");

    if (private.bulk != NULL)
        dqdk_huge_free(ctx, private.bulk, private.max_bulk_size);

    if (private.histo != NULL)
        dqdk_huge_free(ctx, (u8*)private.histo, TRISTAN_HISTO_SZ);

    return dqdk_ctx_fini(ctx);
}
