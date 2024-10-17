// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// #define USE_SIMD

#include <arpa/inet.h>
#include <bpf.h>
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
// #include <rte_memcpy.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "bpf/forwarder.skel.h"
#include "dqdk-blk.h"
#include "dqdk-sys.h"
#include "tcpip/ipv4.h"
#include "tcpip/udp.h"
#include "dqdk.h"
#include "tristan.h"

typedef struct {
    xsk_info_t* xsk;
    tristan_mode_t tristan_mode;
} dqdk_ctx_t;

#define UMEM_FACTOR 64
#define UMEM_LEN (XSK_RING_PROD__DEFAULT_NUM_DESCS * UMEM_FACTOR)
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE

#define MAX_QUEUES 16

#define UMEM_SIZE (UMEM_LEN * FRAME_SIZE)
#define FILLQ_LEN UMEM_LEN
#define COMPQ_LEN XSK_RING_PROD__DEFAULT_NUM_DESCS

#define UMEM_FLAGS_USE_HGPG (1 << 0)
#define UMEM_FLAGS_UNALIGNED (1 << 1)
#define LARGE_MEMSZ ((u64)100 * 1024 * 1024 * 1024)

volatile u32 break_flag = 0;

static void* umem_buffer_create(u32 size, u8 flags, int driver_numa)
{
    return flags & UMEM_FLAGS_USE_HGPG ? huge_malloc(driver_numa, size) : mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static umem_info_t* umem_info_create(u32 size, u8 flags, int driver_numa)
{
    umem_info_t* info = (umem_info_t*)calloc(1, sizeof(umem_info_t));

    info->size = size;
    info->buffer = umem_buffer_create(info->size, flags, driver_numa);
    if (info->buffer == NULL) {
        dlog_error2("umem_buffer_create", 0);
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

static int xsk_configure(xsk_info_t* xsk, const char* ifname)
{
    int ret = 0;
    const struct xsk_socket_config xsk_config = {
        .rx_size = FILLQ_LEN,
        .tx_size = COMPQ_LEN,
        .bind_flags = xsk->bind_flags,
        .libbpf_flags = xsk->libbpf_flags,
        .xdp_flags = xsk->xdp_flags
    };

    struct xsk_ring_prod* fq = &xsk->umem_info->fq0;
    struct xsk_ring_cons* cq = &xsk->umem_info->cq0;

    ret = xsk_socket__create_shared(&xsk->socket, ifname, xsk->queue_id,
        xsk->umem_info->umem, &xsk->rx, &xsk->tx, fq, cq, &xsk_config);
    if (ret) {
        dlog_error2("xsk_socket__create", ret);
        return ret;
    }

    if (xsk->busy_poll) {
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
    }

    return 0;
}

static int fq_ring_configure(xsk_info_t* xsk)
{
    // push all frames to fill ring
    u32 idx = 0, ret, fqlen = FILLQ_LEN;

    struct xsk_ring_prod* fq = &xsk->umem_info->fq0;

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

always_inline u8* get_udp_payload(xsk_info_t* xsk, u8* buffer, u32 len, u32* datalen)
{
    struct ethhdr* frame = (struct ethhdr*)buffer;
    u16 ethertype = ntohs(frame->h_proto);

    if (ethertype != ETH_P_IP) {
        return NULL;
    }

    ++xsk->stats.rcvd_pkts;
    struct iphdr* packet = (struct iphdr*)(frame + 1);
    if (packet->version != 4) {
        return NULL;
    }

    if (packet->protocol != IPPROTO_UDP) {
        return NULL;
    }

    if (!ip4_audit(packet, len - sizeof(struct ethhdr))) {
        ++xsk->stats.invalid_ip_pkts;
        return NULL;
    }

    u32 iphdrsz = ip4_get_header_size(packet);
    u32 udplen = ntohs(packet->tot_len) - iphdrsz;
    struct udphdr* udp = (struct udphdr*)(((u8*)packet) + iphdrsz);

    if (!udp_audit(udp, packet->saddr, packet->daddr, udplen)) {
        xsk->stats.invalid_udp_pkts++;
        return NULL;
    }

    *datalen = udplen - sizeof(struct udphdr);
    return (u8*)(udp + 1);
}

static always_inline int do_daq(xsk_info_t* xsk, umem_info_t* umem, tristan_mode_t mode)
{
    u32 idx_rx = 0, idx_fq = 0, datalen = 0;
    struct xsk_ring_prod* fq = &umem->fq0;

    int rcvd = xsk_ring_cons__peek(&xsk->rx, xsk->batch_size, &idx_rx);
    if (!rcvd) {
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

    for (int i = 0; i < rcvd; ++i) {
        u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->len;
        u8* frame = xsk_umem__get_data(umem->buffer, addr);
        u8* data = get_udp_payload(xsk, frame, len, &datalen);

        if (datalen != 0 && data != NULL) {
            switch (mode) {
            case TRISTAN_MODE_WAVEFORM:
                tristan_daq_waveform((tristan_private_t*)xsk->private, xsk, data, datalen);
                break;
            case TRISTAN_MODE_ENERGYHISTO:
                tristan_daq_energyhisto((tristan_private_t*)xsk->private, xsk, data, datalen);
                break;
            default:
                break;
            }
        }

        ++idx_rx;
        ++idx_fq;
    }

    xsk->stats.rcvd_frames += rcvd;

    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk_ring_prod__submit(fq, rcvd);
    return 0;
}

void* run_daq(void* rxctx_ptr)
{
    dqdk_ctx_t* ctx = (dqdk_ctx_t*)rxctx_ptr;
    xsk_info_t* xsk = ctx->xsk;
    tristan_mode_t mode = ctx->tristan_mode;
    u64 t0, t1;

    t0 = clock_nsecs();
    while (!break_flag) {
        do_daq(xsk, xsk->umem_info, mode);
    }
    t1 = clock_nsecs();

    socklen_t socklen = sizeof(struct xdp_statistics);
    xsk->stats.runtime = t1 - t0;
    int ret = getsockopt(xsk_socket__fd(xsk->socket), SOL_XDP,
        XDP_STATISTICS, &(xsk->stats.xstats), &socklen);
    if (ret) {
        dlog_error2("getsockopt(XDP_STATISTICS)", ret);
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
    printf("    Total runtime (ns):       %llu\n"
           "    Received Frames:          %llu\n"
           "    Average RX L2 PPS:        %f\n"
           "    Received Packets:         %llu\n"
           "    Average RX L3 PPS:        %f\n"
           "    Sent Frames:              %llu\n"
           "    Average TX Frames:        %f\n"
           "    Invalid L3 Packets:       %llu\n"
           "    Invalid L4 Packets:       %llu\n"
           "    Failed Polls:             %llu\n"
           "    Timeout Polls:            %llu\n"
           "    XSK Fill Fail Polls:      %llu\n"
           "    XSK RX Successful Fills:  %llu\n"
           "    XSK TX Successful Fills:  %llu\n"
           "    XSK RXQ Empty:            %llu\n"
           "    XSK TXQ Need Wakeup:      %llu\n"
           "    X-XSK RX Dropped:         %llu\n"
           "    X-XSK RX FillQ Empty:     %llu\n"
           "    X-XSK RX Invalid Descs:   %llu\n"
           "    X-XSK RX Ring Full:       %llu\n"
           "    X-XSK TX Invalid Descs:   %llu\n"
           "    X-XSK TX Ring Empty:      %llu\n"
           "    TRISTAN Out-of-Order:     %llu\n"
           "    TRISTAN Duplicates:       %llu\n"
           "    TRISTAN Hist Events:      %llu\n"
           "    TRISTAN Hist Lost Events: %llu\n",

        stats->runtime, stats->rcvd_frames,
        AVG_PPS(stats->rcvd_frames, stats->runtime), stats->rcvd_pkts,
        AVG_PPS(stats->rcvd_pkts, stats->runtime), stats->sent_frames,
        AVG_PPS(stats->sent_frames, stats->runtime),

        stats->invalid_ip_pkts, stats->invalid_udp_pkts,
        stats->fail_polls, stats->timeout_polls,
        stats->rx_fill_fail_polls, stats->rx_successful_fills,
        stats->tx_successful_fills, stats->rx_empty_polls, stats->tx_wakeup_sendtos,

        stats->xstats.rx_dropped, stats->xstats.rx_fill_ring_empty_descs,
        stats->xstats.rx_invalid_descs, stats->xstats.rx_ring_full,
        stats->xstats.tx_invalid_descs, stats->xstats.tx_ring_empty_descs,
        stats->tristan_outoforder, stats->tristan_dups,
        stats->tristan_histogram_evts, stats->tristan_histogram_lost_evts);
}

void xsk_stats_dump(xsk_info_t* xsk)
{
    printf("XSK %u on Queue %u Statistics:\n", xsk->index, xsk->queue_id);
    stats_dump(&xsk->stats);
}

void dqdk_usage(char** argv)
{
    printf("Usage: %s -i <interface_name> -q <hardware_queue_id>\n", argv[0]);
    printf("Arguments:\n");
    printf("    -d <duration>                Set the run duration in seconds. Default: 3 secs\n");
    printf("    -i <interface>               Set NIC to work on\n");
    printf("    -q <qid[-qid]>               Set range of hardware queues to work on e.g. -q 1 or -q 1-3.\n");
    printf("                                 Specifying multiple queues will launch a thread for each queue except if -p poll\n");
    printf("    -v                           Verbose\n");
    printf("    -b <size>                    Set batch size. Default: 64\n");
    printf("    -w                           Use XDP need wakeup flag\n");
    printf("    -s                           Expected Packet Size. Default: 3392\n");
    printf("    -A <irq1,irq2,...>           Set affinity mapping between application threads and drivers queues\n");
    printf("                                 e.g. q1 to irq1, q2 to irq2,...\n");
    printf("    -B                           Enable NAPI busy-poll\n");
    printf("    -H                           Considering Hyper-threading is enabled, this flag will assign affinity\n");
    printf("                                 of softirq and the app to two logical cores of the same physical core.\n");
    printf("    -G                           Activate Huge Pages for UMEM allocation\n");
    printf("    -S                           Run IRQ and App on same core\n");
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
        // if (smt) {
        //     dlog_error("Hyper-Threading is enabled but not chosen in the configuration");
        //     return (u32)-1;
        // }

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

int main(int argc, char** argv)
{
    // options values
    char* opt_ifname = NULL;
    u32 opt_batchsize = 64, opt_queues[MAX_QUEUES] = { -1 },
        opt_irqs[MAX_QUEUES] = { -1 };
    struct itimerspec opt_duration = {
        .it_interval.tv_sec = DQDK_DURATION,
        .it_interval.tv_nsec = 0,
        .it_value.tv_sec = opt_duration.it_interval.tv_sec,
        .it_value.tv_nsec = 0
    };
    u8 opt_needs_wakeup = 0, opt_verbose = 0, opt_hyperthreading = 0,
       opt_samecore = 0, opt_busy_poll = 0, opt_umem_flags = 0, opt_debug = 0;
    int opt_selnumanode = 0, opt_packetsz = 3392;

    // program variables
    tristan_mode_t mode = TRISTAN_MODE_WAVEFORM;
    tristan_private_t private = { 0 };
    int ifindex = -1, ret, opt, timer_flag = -1;
    u32 nbqueues = 0, nbirqs = 0, nprocs = 0, umem_size = UMEM_SIZE;
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    struct forwarder* forwarder = NULL;
    struct xdp_program* kern_prog = NULL;
    struct xdp_options xdp_opts;
    pthread_t* xsk_workers = NULL;
    pthread_attr_t* xsk_worker_attrs = NULL;
    cpu_set_t* cpusets = NULL;
    xsk_info_t* xsks = NULL;
    dqdk_ctx_t* ctxs = NULL;
    timer_t timer;
    socklen_t socklen;
    // NUMA
    int is_numa = 0;
    int driver_numa_node = 0;
    unsigned long cpu_mask = 0;
    u8 selnumanode = 0, finished = 0;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGUSR1, signal_handler);

    if (argc == 1) {
        dqdk_usage(argv);
        return 0;
    }

    while ((opt = getopt(argc, argv, "b:d:hi:q:vws:A:BM:DHGSN:")) != -1) {
        switch (opt) {
        case 'h':
            dqdk_usage(argv);
            return 0;
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
            timer_flag = 1;
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
        case 's':
            opt_packetsz = atoi(optarg);
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
        case 'N':
            selnumanode = 1;
            opt_selnumanode = atoi(optarg);
            break;
        case 'M':
            if (strcmp(optarg, "energy-histo") == 0) {
                mode = TRISTAN_MODE_ENERGYHISTO;
            } else if (strcmp(optarg, "waveform") == 0) {
                mode = TRISTAN_MODE_WAVEFORM;
            } else {
                dlog_errorv("Unknown TRISTAN mode: %s", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'D':
            opt_debug = 1;
            break;
        default:
            dqdk_usage(argv);
            dlog_error("Invalid Arg\n");
            exit(EXIT_FAILURE);
        }
    }

    if (opt_ifname == NULL || nbqueues == 0) {
        dlog_error("Invalid interface name or number of queues");
        goto cleanup;
    }

    driver_numa_node = nic_numa_node(opt_ifname);
    is_numa = numa_available();
    if (is_numa < 0) {
        nprocs = get_nprocs();
    } else {
        dlog_infov("NUMA is detected! %s is owned by node %d", opt_ifname, driver_numa_node);

        if (selnumanode)
            driver_numa_node = opt_selnumanode;
        else if (driver_numa_node == -1)
            driver_numa_node = 0; // failure to get numa node or PCI is equidistant to all NUMA nodes => assign node0

        dlog_infov("Selected NUMA node is %d", driver_numa_node);

        if (opt_selnumanode > -1) {
            numa_set_bind_policy(1);
            struct bitmask* nodemask = numa_allocate_nodemask();
            struct bitmask* fromnodemask = numa_allocate_nodemask();

            numa_bitmask_clearall(nodemask);
            numa_bitmask_setbit(nodemask, driver_numa_node);
            numa_bind(nodemask);

            numa_bitmask_setall(fromnodemask);
            numa_bitmask_clearbit(fromnodemask, driver_numa_node);
            numa_migrate_pages(getpid(), fromnodemask, nodemask);

            numa_free_nodemask(fromnodemask);
            numa_free_nodemask(nodemask);

            struct bitmask* cpumask = numa_allocate_cpumask();
            numa_node_to_cpus(driver_numa_node, cpumask);
            cpu_mask = *cpumask->maskp;
            numa_free_cpumask(cpumask);
            nprocs = popcountl(cpu_mask);
        } else {
            // FIXME: we should allocate numa-aware memory
            numa_set_bind_policy(0);
            cpu_mask = (unsigned long)-1;
            nprocs = get_nprocs();
        }
        dlog_infov("NUMA CPU Mask is %#010lX of %d CPUs", cpu_mask, nprocs);
    }

    (opt_umem_flags & UMEM_FLAGS_USE_HGPG) ? dlog_info("Huge pages are activated!") : dlog_info("No huge pages are used!");

    if (ifindex < 0) {
        dlog_error("Invalid NIC index\n");
        goto cleanup;
    }

    if (nbirqs != nbqueues) {
        dlog_errorv("IRQs=%d and number of queues=%d must be equal", nbirqs, nbqueues);
        goto cleanup;
    }

    if (nbirqs > nprocs) {
        dlog_error("IRQs should be smaller or equal to number of processors");
        goto cleanup;
    }

    if (!opt_samecore && nbqueues * 2 > nprocs) {
        dlog_errorv("IRQs and Application threads are running on different cores. You should have enough dedicated cores for both of them. The maximum possible cores now is %d", nprocs);
        goto cleanup;
    }

    if (opt_verbose) {
        libbpf_set_print(infoprint);
    }

    u32 nbxsks = nbqueues;
    char queues[4 * MAX_QUEUES] = { 0 };
    char* queues_format = queues;
    for (u32 i = 0; i < nbqueues; i++) {
        ret = (i == nbqueues - 1) ? snprintf(queues_format, 2, "%d", opt_queues[i])
                                  : snprintf(queues_format, 4, "%d, ", opt_queues[i]);
        queues_format += ret;
    }

    dlog_info("Per-queue routing to XSK.");
    dlog_infov("Working %d XSKs on queues: %s", nbqueues, queues);

    dlog_info_head("IRQ-to-Queue Mappings: ");
    for (size_t i = 0; i < nbirqs; i++) {
        if (i != nbirqs - 1) {
            dlog_info_print("%d-%d, ", opt_irqs[i], opt_queues[i]);
        } else {
            dlog_info_print("%d-%d", opt_irqs[i], opt_queues[i]);
        }
    }
    dlog_info_exit();

    if ((ret = setrlimit(RLIMIT_MEMLOCK, &rlim))) {
        dlog_error2("setrlimit", ret);
        goto cleanup;
    }

    forwarder = forwarder__open();
    forwarder->bss->expected_udp_data_sz = htons(opt_packetsz);

    kern_prog = xdp_program__from_bpf_obj(forwarder->obj, NULL);
    ret = xdp_program__attach(kern_prog, ifindex, XDP_MODE_NATIVE, 0);
    if (ret < 0) {
        kern_prog = NULL;
        dlog_error2("xdp_program__attach", ret);
        goto cleanup;
    }

    xsk_workers = (pthread_t*)calloc(nbxsks, sizeof(pthread_t));
    xsks = (xsk_info_t*)calloc(nbxsks, sizeof(xsk_info_t));
    ctxs = (dqdk_ctx_t*)calloc(nbxsks, sizeof(dqdk_ctx_t));
    xsk_worker_attrs = (pthread_attr_t*)calloc(nbxsks, sizeof(pthread_attr_t));
    cpusets = (cpu_set_t*)calloc(nbxsks, sizeof(cpu_set_t));

    if (timer_flag > 0) {
        struct sigevent sigv;
        sigv.sigev_notify = SIGEV_SIGNAL;
        sigv.sigev_signo = SIGUSR1;
        timer_create(CLOCK_MONOTONIC, &sigv, &timer);
        timer_settime(timer, 0, &opt_duration, NULL);
    }

    if (mode == TRISTAN_MODE_ENERGYHISTO || mode == TRISTAN_MODE_LISTWAVE) {
        private.histo = (tristan_histo_t*)huge_malloc(driver_numa_node, TRISTAN_HISTO_SZ);
    }

    // TODO: What is the size of allocation? It is parameterizable
    // if (mode == TRISTAN_MODE_WAVEFORM || mode == TRISTAN_MODE_LISTWAVE) {
    //     private.bulk = huge_malloc(driver_numa_node, xx);
    // }

    for (u32 i = 0; i < nbxsks; i++) {
        xsks[i].batch_size = opt_batchsize;
        xsks[i].busy_poll = opt_busy_poll;
        xsks[i].libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
        xsks[i].bind_flags = (opt_needs_wakeup ? XDP_USE_NEED_WAKEUP : 0);
        xsks[i].xdp_flags = 0;
        xsks[i].queue_id = opt_queues[i];
        xsks[i].index = i;
        xsks[i].debug = opt_debug;
        xsks[i].private = &private;

        xsks[i].umem_info = umem_info_create(umem_size, opt_umem_flags, driver_numa_node);
        ret = umem_configure(xsks[i].umem_info);
        if (ret) {
            goto cleanup;
        }

        ret = xsk_configure(&xsks[i], opt_ifname);
        if (ret) {
            dlog_error2("xsk_configure", ret);
            goto cleanup;
        }

        ret = fq_ring_configure(&xsks[i]);
        if (ret) {
            dlog_error2("fq_ring_configure", ret);
            goto cleanup;
        }

        u32 sockfd = xsk_socket__fd(xsks[i].socket);
        u32 mapkey = xsks[i].queue_id;
        ret = bpf_map__update_elem(forwarder->maps.xsks_map, &mapkey, sizeof(u32), &sockfd, sizeof(u32), BPF_ANY);
        if (ret) {
            dlog_error2("bpf_map__update_elem", ret);
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

        pthread_attr_t* attrs = &xsk_worker_attrs[i];

        pthread_attr_init(attrs);
        // Set process and interrupt affinity to same CPU
        ret = dqdk_set_affinity(opt_hyperthreading, opt_samecore, opt_irqs[i], &cpu_mask, &cpusets[i], attrs);
        if (ret)
            goto cleanup;

        dqdk_ctx_t* ctx = &ctxs[i];
        ctx->xsk = &xsks[i];
        ctx->tristan_mode = mode;
        pthread_create(&xsk_workers[i], attrs, run_daq, (void*)ctx);
    }

    struct xsk_stat avg_stats;
    memset(&avg_stats, 0, sizeof(avg_stats));
    for (u32 i = 0; i < nbxsks; i++) {
        pthread_join(xsk_workers[i], NULL);

        xsk_stats_dump(&xsks[i]);
        avg_stats.runtime = MAX(avg_stats.runtime, xsks[i].stats.runtime);
        avg_stats.rcvd_pkts += xsks[i].stats.rcvd_pkts;
        avg_stats.rcvd_frames += xsks[i].stats.rcvd_frames;
        avg_stats.sent_frames += xsks[i].stats.sent_frames;

        avg_stats.fail_polls += xsks[i].stats.fail_polls;
        avg_stats.invalid_ip_pkts += xsks[i].stats.invalid_ip_pkts;
        avg_stats.invalid_udp_pkts += xsks[i].stats.invalid_udp_pkts;
        avg_stats.rx_empty_polls += xsks[i].stats.rx_empty_polls;
        avg_stats.rx_fill_fail_polls += xsks[i].stats.rx_fill_fail_polls;
        avg_stats.timeout_polls += xsks[i].stats.timeout_polls;
        avg_stats.tx_wakeup_sendtos += xsks[i].stats.tx_wakeup_sendtos;
        avg_stats.rx_successful_fills += xsks[i].stats.rx_successful_fills;
        avg_stats.tx_successful_fills += xsks[i].stats.tx_successful_fills;

        avg_stats.xstats.rx_dropped += xsks[i].stats.xstats.rx_dropped;
        avg_stats.xstats.rx_invalid_descs += xsks[i].stats.xstats.rx_invalid_descs;
        avg_stats.xstats.tx_invalid_descs += xsks[i].stats.xstats.tx_invalid_descs;
        avg_stats.xstats.rx_ring_full += xsks[i].stats.xstats.rx_ring_full;
        avg_stats.xstats.rx_fill_ring_empty_descs += xsks[i].stats.xstats.rx_fill_ring_empty_descs;
        avg_stats.xstats.tx_ring_empty_descs += xsks[i].stats.xstats.tx_ring_empty_descs;

        avg_stats.tristan_outoforder += xsks[i].stats.tristan_outoforder;
        avg_stats.tristan_dups += xsks[i].stats.tristan_dups;
        avg_stats.tristan_histogram_evts += xsks[i].stats.tristan_histogram_evts;
        avg_stats.tristan_histogram_lost_evts += xsks[i].stats.tristan_histogram_lost_evts;
    }

    finished = 1;

    if (nbxsks != 1) {
        printf("Average Stats:\n");
        stats_dump(&avg_stats);
    }

    dqdk_blk_t* blk = dqdk_blk_init(DQDK_BLK_QUEUE_DEPTH);
    if (private.histo) {
        dqdk_blk_status_t stats = dqdk_blk_dump(blk, "tristan-histo.bin", FILE_BSIZE, TRISTAN_HISTO_SZ, private.histo);
        if (stats.status != 0)
            dlog_infov("DQDK-BLK Object dumping failed, returned %d\n", stats.status);
    }

    if (private.bulk) {
        dqdk_blk_status_t stats = dqdk_blk_dump(blk, "tristan-raw.bin", FILE_BSIZE, private.bulk_size, private.bulk);
        if (stats.status != 0)
            dlog_infov("DQDK-BLK Object dumping failed, returned %d\n", stats.status);
    }

    dqdk_blk_fini(blk);

cleanup:
    /**
     * in case some thread were running but others failed
     * (e.g. when launching with 4 queues but only 2 are available)
     * break the running ones so we do not cause a segfault by
     * freeing data for the running ones
     */
    if (!finished && xsk_workers != NULL) {
        break_flag = 1;
        for (u32 i = 0; i < nbxsks; i++)
            pthread_join(xsk_workers[i], NULL);
    }

    if (ctxs != NULL)
        free(ctxs);

    if (timer_flag > 0)
        timer_delete(timer);

    if (kern_prog != NULL) {
        forwarder__destroy(forwarder);
        xdp_program__detach(kern_prog, ifindex, XDP_MODE_NATIVE, 0);
        xdp_program__close(kern_prog);
    }

    if (xsks != NULL) {
        for (size_t i = 0; i < nbxsks; i++) {
            xsk_info_t xsk = xsks[i];
            xsk_socket__delete(xsk.socket);

            if (xsk.umem_info != NULL) {
                umem_info_free(xsk.umem_info);
                free(xsk.umem_info);
            }

            if (xsk.large_mem != NULL) {
                // munmap(large_mem, LARGE_MEMSZ);
                free(xsk.large_mem);
            }

            if (xsk.private != NULL)
                munmap(xsk.private, TRISTAN_HISTO_SZ);
        }
        free(xsks);

        if (xsk_workers != NULL)
            free(xsk_workers);
    }

    if (xsk_worker_attrs != NULL) {
        for (size_t i = 0; i < nbxsks; i++)
            pthread_attr_destroy(&xsk_worker_attrs[i]);

        free(xsk_worker_attrs);
    }

    if (cpusets != NULL)
        free(cpusets);

    if (private.histo != NULL)
        munmap(private.histo, TRISTAN_HISTO_SZ);

    if (private.histo != NULL || (opt_umem_flags & UMEM_FLAGS_USE_HGPG))
        set_hugepages(driver_numa_node, 0);
}
