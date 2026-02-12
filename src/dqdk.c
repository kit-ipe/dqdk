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
#include <sys/user.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <linux/net_tstamp.h>
#include <sys/stat.h>

#define BPF_F_XDP_DEV_BOUND_ONLY (1U << 6)

#include "bpf/forwarder.skel.h"
#include "tcpip/ipv4.h"
#include "tcpip/udp.h"
#include "dqdk-sys.h"
#include "dqdk-mem.h"
#include "dqdk.h"

#define FILLQ_LEN UMEM_LEN
#define COMPQ_LEN XSK_RING_PROD__DEFAULT_NUM_DESCS

volatile u32 break_flag = 0;

static umem_info_t* umem_info_create(dqdk_ctx_t* ctx)
{
    umem_info_t* info = (umem_info_t*)calloc(1, sizeof(umem_info_t));

    info->size = ctx->umem_size;
    info->buffer = ctx->umem_flags & UMEM_FLAGS_USE_HGPG ? dqdk_2mbhuge_malloc(ctx->numa_node, ctx->umem_size) : dqdk_malloc(ctx->umem_size, 0);
    if (info->buffer == NULL) {
        dlog_error2("umem_buffer_create", 0);
        free(info);
        return NULL;
    }

    info->umem = NULL;
    info->flags = ctx->umem_flags;
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

#define WORKER_LATENCY(worker, param, latency)                                                                                  \
    do {                                                                                                                        \
        (worker)->stats.param.sum += (latency);                                                                                 \
        (worker)->stats.param.max = MAX((worker)->stats.param.max, (latency));                                                  \
        if ((latency) > 0)                                                                                                      \
            (worker)->stats.param.min = (worker)->stats.param.min == 0 ? (latency) : MIN((worker)->stats.param.min, (latency)); \
        if (((worker)->debug_flags & DQDK_DEBUG_LATENCYDUMP)                                                                    \
            && ((worker)->stats.param.raw_idx) < DQDK_MAX_LATENCY_METRICS)                                                      \
            (worker)->stats.param.raw[(worker)->stats.param.raw_idx++] = latency;                                               \
    } while (0)

static int post_async(dqdk_worker_t* xsk, u8* data, u32 datalen)
{
    int ret = cne_ring_enqueue_elem(xsk->ring, data, datalen);
    if (ret < 0) {
        dlog_error("Ring Buffer is full");
        return -1;
    }

    return ret;
}

static dqdk_always_inline int process_frame(dqdk_worker_t* xsk, u8* frame, u32 len)
{
    int ret = 0;
    u32 datalen = 0;
    u8* data = get_udp_payload(xsk, frame, len, &datalen);

    if (xsk->debug_flags && xsk->soft_timestamp != BAD_CLOCK) {
        u64 t0 = *((u64*)frame); // Get hardware timestamp
        s64 latency = xsk->soft_timestamp - t0;
        WORKER_LATENCY(xsk, queuing_latency, latency);
    }

    ret = xsk->frame_processor ? xsk->frame_processor(xsk, data, datalen) : post_async(xsk, data, datalen);
    if (!ret)
        xsk->stats.rcvd_bytes += datalen;

    return ret;
}

static dqdk_always_inline int fetch_xsk(dqdk_worker_t* xsk)
{
    int ret = 0;
    umem_info_t* umem = xsk->umem_info;
    u32 idx_rx = 0, idx_fq;
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

        ret = -ECOMM;
        goto exit;
    }

    ret = xsk_ring_prod__reserve(fq, rcvd, &idx_fq);
    while (ret != rcvd) {
        if (xsk->busy_poll || xsk_ring_prod__needs_wakeup(fq)) {
            xsk->stats.rx_fill_fail_polls++;
            recvfrom(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }

        ret = xsk_ring_prod__reserve(fq, rcvd, &idx_fq);
    }

    ++xsk->stats.rx_successful_fills;
    xsk->stats.rcvd_frames += rcvd;

    for (int i = 0; i < rcvd; i++) {
        const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
        u8* frame = xsk_umem__get_data(xsk->umem_info->buffer, desc->addr);
        if (process_frame(xsk, frame, desc->len) < 0) {
            ret = -1;
            goto exit;
        }
    }

    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk_ring_prod__submit(fq, rcvd);

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

exit:
    if (ret < 0)
        xsk->stats.failing_batches++;

    return ret;
}

static int daq_loop(dqdk_worker_t* xsk)
{
    u64 t0, t1;

    t0 = clock_nsecs_mono();
    while (dqdk_unlikely(!break_flag)) {
        fetch_xsk(xsk);
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
    case SIGHUP:
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
    printf("    Total Processed Bytes:    %llu\n", stats->rcvd_bytes);
    printf("    Invalid L3 Packets:       %llu\n", stats->invalid_ip_pkts);
    printf("    Invalid L4 Packets:       %llu\n", stats->invalid_udp_pkts);
    printf("    Empty Batches:            %llu\n", stats->failing_batches);
    printf("    L3 Packets per Second:    %.3f\n", AVG_PPS(stats->rcvd_pkts, stats->runtime));
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
        app_aff = samecore ? irq_aff : dqdk_get_next_core(cpumask);
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

    if (!ctx->barrier_init || (ret = pthread_barrier_wait(&ctx->barrier)) > 0) {
        dlog_error2("pthread_barrier_wait", ret);
        goto error;
    }

    ret = daq_loop(xsk);
    if (ret >= 0)
        goto cleanup;

error:
    dlog_errorv("Worker %d is dead!", xsk->index);
    if (!ctx->barrier_init || (ret = pthread_barrier_wait(&ctx->barrier)) > 0)
        dlog_error2("pthread_barrier_wait", ret);

cleanup:
    free(wobj);
    return (void*)(long)ret;
}

int dqdk_worker_init(dqdk_ctx_t* ctx, int qid, int irq, void* private)
{
    static int worker_index = 0;
    int ret;

    dqdk_worker_t* xsk = calloc(1, sizeof(dqdk_worker_t));
    if (xsk == NULL) {
        ret = -1;
        goto error;
    }

    ctx->workers[worker_index] = xsk;

    struct worker_obj* wobj = calloc(1, sizeof(struct worker_obj));
    if (wobj == NULL) {
        ret = -1;
        goto error;
    }

    wobj->ctx = ctx;
    wobj->xsk = xsk;

    xsk->private = private;
    xsk->frame_processor = ctx->frame_processor;
    xsk->queue_id = qid;
    xsk->index = worker_index++;
    xsk->ring = ctx->ring;
    xsk->batch_size = ctx->batch_size;
    xsk->busy_poll = ctx->busy_poll;
    xsk->debug_flags = ctx->debug_flags;
    xsk->thread_attrs = calloc(1, sizeof(pthread_attr_t));
    if (xsk->thread_attrs == NULL) {
        ret = -1;
        goto error;
    }

    if (xsk->debug_flags & DQDK_DEBUG_LATENCYDUMP) {
        xsk->stats.queuing_latency.raw = calloc(DQDK_MAX_LATENCY_METRICS, sizeof(s64));
        xsk->stats.processing_latency.raw = calloc(DQDK_MAX_LATENCY_METRICS, sizeof(s64));
        if (xsk->stats.processing_latency.raw == NULL || xsk->stats.queuing_latency.raw == NULL) {
            ret = -1;
            goto error;
        }
    }

    xsk->umem_info = umem_info_create(ctx);
    if (xsk->umem_info == NULL) {
        dlog_error("Error allocating umem");
        ret = -1;
        goto error;
    }

    ret = umem_configure(xsk->umem_info);
    if (ret)
        return -1;

    ret = xsk_configure(ctx, xsk);
    if (ret) {
        dlog_error2("xsk_configure", ret);
        ret = -1;
        goto error;
    }

    u32 sockfd = xsk_socket__fd(xsk->socket);
    u32 mapkey = xsk->queue_id;
    ret = bpf_map__update_elem(ctx->forwarder->maps.xsks_map, &mapkey, sizeof(u32), &sockfd, sizeof(u32), BPF_ANY);
    if (ret) {
        dlog_error2("bpf_map__update_elem", ret);
        ret = -1;
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

    ret = pthread_attr_init(xsk->thread_attrs);
    if (ret) {
        ret = -1;
        goto error;
    }

    ret = dqdk_set_affinity(ctx->hyperthreading, ctx->samecore, irq, &ctx->cpu_mask, &xsk->cset, xsk->thread_attrs);
    if (ret) {
        ret = -1;
        goto error;
    }

    ret = pthread_create(&xsk->thread, xsk->thread_attrs, dqdk_worker, (void*)wobj);
    if (!ret)
        return 0;
error:
    return ret;
}

static int dqdk_ctx_free(dqdk_ctx_t* ctx)
{
    if (ctx == NULL)
        return -1;

    if (ctx->ifname != NULL)
        free(ctx->ifname);

    if (ctx->forwarder != NULL) {
        LIBBPF_OPTS(bpf_xdp_attach_opts, opts, .old_prog_fd = bpf_program__fd(ctx->forwarder->progs.dqdk_forwarder));
        int ret = bpf_xdp_detach(ctx->ifindex, ctx->xmode, &opts);
        if (ret < 0)
            dlog_error2("bpf_xdp_detach", ret);
        forwarder__destroy(ctx->forwarder);
    }

    if (ctx->workers != NULL)
        free(ctx->workers);

    if (ctx->ring)
        cne_ring_free(ctx->ring);

    if (ctx->ring_buffer)
        dqdk_free(ctx->ring_buffer, ctx->ringsz);

    if (ctx->barrier_init)
        pthread_barrier_destroy(&ctx->barrier);

    set_hugepages(ctx->numa_node, 0, PAGE_2MB);
    set_hugepages(ctx->numa_node, 0, PAGE_1GB);

    free(ctx);
    return 0;
}

int dqdk_waitall(dqdk_ctx_t* ctx)
{
    dqdk_worker_t* worker;
    break_flag = 1;

    void* thread_ret_ptr = NULL;
    if (!ctx)
        return -EINVAL;

    int ret = 0;
    for (u32 _i = 0; _i < ctx->nbqueues; _i++) {
        worker = ctx->workers[_i];
        if (worker) {
            pthread_join(worker->thread, &thread_ret_ptr);
            if (thread_ret_ptr != NULL) {
                dlog_errorv("Worker %d failed and exited", worker->index);
                ret |= (long)thread_ret_ptr;
            }
        }
    }

    return ret ? -EFAULT : 0;
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

dqdk_ctx_t* dqdk_ctx_init(char* ifname, u32 queues[], u32 nbqueues, u8 umem_flags, u64 umem_size, u32 batch_size, u32 payloadsz, u64 ringsz, dqdk_frame_processor_t frame_processor, dqdk_ctx_opt_t* opts)
{
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    dqdk_ctx_t* ctx = calloc(1, sizeof(dqdk_ctx_t));
    int ret = 0;
    u32 nprocs;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGUSR1, signal_handler);

    if (ifname == NULL || nbqueues == 0) {
        dlog_error("Invalid interface name or number of queues");
        dqdk_ctx_free(ctx);
        return NULL;
    }

    ctx->huge_allocations = 0;
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
    if (opts) {
        switch (opts->xdp_mode) {
        case XDP_MODE_NATIVE:
            ctx->xmode = XDP_FLAGS_DRV_MODE;
            break;

        case XDP_MODE_SKB:
            ctx->xmode = XDP_FLAGS_SKB_MODE;
            break;

        default:
            dlog_error("Invalid XDP Mode");
            dqdk_ctx_free(ctx);
            return NULL;
        }
        ctx->needs_wakeup = opts->needs_wakeup;
        ctx->hyperthreading = opts->hyperthreading;
        ctx->debug_flags = opts->debug;
        ctx->busy_poll = opts->busypoll;
        ctx->samecore = opts->irqworker_samecore;
    } else {
        ctx->xmode = XDP_FLAGS_DRV_MODE;
        ctx->needs_wakeup = opts->needs_wakeup;
        ctx->hyperthreading = opts->hyperthreading;
        ctx->debug_flags = opts->debug;
        ctx->busy_poll = opts->busypoll;
        ctx->samecore = opts->irqworker_samecore;
    }

    ctx->frame_processor = frame_processor;
    ctx->batch_size = batch_size;
    ctx->nbqueues = nbqueues;
    ctx->payloadsz = payloadsz;
    ctx->ifspeed = dqdk_get_link_speed(ctx->ifname);
    ctx->umem_flags = umem_flags;
    ctx->umem_size = umem_size;
    ctx->libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
    ctx->bind_flags = (ctx->needs_wakeup ? XDP_USE_NEED_WAKEUP : 0) | (ctx->xmode == XDP_MODE_SKB ? XDP_COPY : 0);
    ctx->xdp_flags = 0;

    if (ctx->ifspeed < 0) {
        dlog_error("Error fetching link speed");
        dqdk_ctx_free(ctx);
        return NULL;
    }

    dlog_infov("Selected Interface (%s) Speed=%dMbps", ctx->ifname, ctx->ifspeed);

    ctx->numa_node = nic_numa_node(ifname);
    int is_numa = numa_available();
    if (is_numa < 0)
        nprocs = get_nprocs();
    else {
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

    if (ctx->frame_processor) {
        ctx->ring = NULL;
        ctx->ringsz = 0;
        ctx->ring_buffer = NULL;
    } else {
        u64 count = dqdk_calc_ring_count(ringsz, ctx->payloadsz);
        ctx->ringsz = dqdk_calc_ring_size(count, payloadsz);
        double time_capacity = dqdk_calc_ring_msec_capacity(ctx->ringsz, ctx->ifspeed);
        dlog_infov("Allocating ring buffer size=%llu for %llu elements enough for %lf milliseconds", ctx->ringsz, count, time_capacity);
        if (ctx->umem_flags & UMEM_FLAGS_USE_HGPG) {
            dlog_info("Huge pages are activated!");
            ctx->ring_buffer = dqdk_2mbhuge_malloc(ctx->numa_node, ctx->ringsz);
        } else
            ctx->ring_buffer = dqdk_malloc(ctx->ringsz, 0);

        if (!ctx->ring_buffer) {
            dlog_error("Error allocating huge pages memory for ring buffer");
            dqdk_ctx_free(ctx);
            return NULL;
        }

        dlog_info("Initializing ring buffer");
        ctx->ring = cne_ring_init(ctx->ring_buffer, ctx->ringsz, ctx->payloadsz, count, 0);
        if (!ctx->ring) {
            dlog_error2("cne_ring_init", -1);
            dqdk_ctx_free(ctx);
            return NULL;
        }
        dlog_info("Finished initializing ring buffer");
    }

    if (!ctx->samecore && nbqueues * 2 > nprocs) {
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
    ctx->forwarder->bss->debug = ctx->debug_flags;

    bpf_program__set_ifindex(ctx->forwarder->progs.dqdk_forwarder, ctx->ifindex);
    bpf_program__set_flags(ctx->forwarder->progs.dqdk_forwarder, BPF_F_XDP_DEV_BOUND_ONLY);
    bpf_program__set_type(ctx->forwarder->progs.dqdk_forwarder, BPF_PROG_TYPE_XDP);
    ret = forwarder__load(ctx->forwarder);
    if (ret < 0) {
        dlog_error2("forwarder__load", ret);
        dqdk_ctx_free(ctx);
        return NULL;
    }

    LIBBPF_OPTS(bpf_xdp_attach_opts, xopts, .old_prog_fd = -1);
    ret = bpf_xdp_attach(ctx->ifindex, bpf_program__fd(ctx->forwarder->progs.dqdk_forwarder), ctx->xmode, &xopts);
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
    return ctx;
}

int dqdk_for_ports_range(dqdk_ctx_t* ctx, u16 start, u16 end)
{
    if (!ctx || !ctx->forwarder)
        return -EINVAL;

    ctx->forwarder->bss->start_port = start;
    ctx->forwarder->bss->end_port = end;

    ctx->nbports = end - start + 1;
    return 0;
}

int dqdk_start(dqdk_ctx_t* ctx)
{
    int ret = 0;
    if (!ctx) {
        ret = -1;
        goto error;
    }

    if (ctx->nbports == 0) {
        dlog_error("Please provide a range of source ports to accept data on");
        ret = -1;
        goto error;
    }

    if (!ctx->barrier_init || pthread_barrier_wait(&ctx->barrier) > 0) {
        ret = -1;
        goto error;
    }

error:
    return ret;
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

    return dqdk_ctx_free(ctx);
}

void dqdk_dump_stats(dqdk_ctx_t* ctx)
{
    dqdk_stats_t avg;

    if (ctx == NULL)
        return;

    memset(&avg, 0, sizeof(avg));

    for (u32 i = 0; i < ctx->nbqueues; i++) {
        if (ctx->workers[i])
            xsk_stats_dump(ctx->workers[i]);

        dqdk_stats_t* wstats = dqdk_worker_stats(ctx, i);
        if (wstats) {
            avg.runtime = MAX(avg.runtime, wstats->runtime);
            avg.rcvd_pkts += wstats->rcvd_pkts;
            avg.rcvd_frames += wstats->rcvd_frames;
            avg.rcvd_bytes += wstats->rcvd_bytes;
            avg.failing_batches += wstats->failing_batches;

            avg.fail_polls += wstats->fail_polls;
            avg.invalid_ip_pkts += wstats->invalid_ip_pkts;
            avg.invalid_udp_pkts += wstats->invalid_udp_pkts;
            avg.rx_empty_polls += wstats->rx_empty_polls;
            avg.rx_fill_fail_polls += wstats->rx_fill_fail_polls;
            avg.timeout_polls += wstats->timeout_polls;
            avg.rx_successful_fills += wstats->rx_successful_fills;

            avg.xstats.rx_dropped += wstats->xstats.rx_dropped;
            avg.xstats.rx_invalid_descs += wstats->xstats.rx_invalid_descs;
            avg.xstats.rx_ring_full += wstats->xstats.rx_ring_full;
            avg.xstats.rx_fill_ring_empty_descs += wstats->xstats.rx_fill_ring_empty_descs;

            avg.queuing_latency.sum += wstats->queuing_latency.sum;
            avg.queuing_latency.min = avg.queuing_latency.min == 0 ? wstats->queuing_latency.min : MIN(avg.queuing_latency.min, wstats->queuing_latency.min);
            avg.queuing_latency.max = MAX(avg.queuing_latency.max, wstats->queuing_latency.max);

            avg.processing_latency.sum += wstats->processing_latency.sum;
            avg.processing_latency.min = avg.processing_latency.min == 0 ? wstats->processing_latency.min : MIN(avg.processing_latency.min, wstats->processing_latency.min);
            avg.processing_latency.max = MAX(avg.processing_latency.max, wstats->processing_latency.max);
        }
    }

    if (ctx->nbqueues != 1) {
        printf("Average Stats:\n");
        stats_dump(&avg, ctx->debug_flags & DQDK_DEBUG);
    }
}

int dqdk_uses_hugepages(dqdk_ctx_t* ctx)
{
    if (!ctx)
        return -EINVAL;
    return ctx->umem_flags & UMEM_FLAGS_USE_HGPG;
}

u32 dqdk_workers_count(dqdk_ctx_t* ctx)
{
    if (!ctx)
        return 0;
    return ctx->nbqueues;
}

dqdk_stats_t* dqdk_worker_stats(dqdk_ctx_t* ctx, u32 worker_index)
{
    if (!ctx)
        return NULL;

    dqdk_worker_t* worker = ctx->workers[worker_index];
    if (!worker)
        return NULL;
    return &worker->stats;
}

double dqdk_calc_ring_msec_capacity(u64 ringsz, int ifspeed) {
    return (ringsz * 8e3) / (ifspeed * (1ULL << 20));
}

double dqdk_ring_msec_capacity(dqdk_ctx_t* ctx)
{
    if (!ctx)
        return 0;

    return dqdk_calc_ring_msec_capacity(ctx->ringsz, ctx->ifspeed);
}

u64 dqdk_calc_ring_count(u64 ringsz, u32 payloadsz)
{
    return get_powerof2(ringsz / payloadsz);
}

u64 dqdk_calc_ring_size(u32 count, u32 payloadsz)
{
    return cne_ring_get_memsize_elem(payloadsz, count);
}
