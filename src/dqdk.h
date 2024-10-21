#ifndef DQDK_TYPES_H
#define DQDK_TYPES_H

#include <linux/mman.h>
#include <linux/limits.h>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <math.h>
#include <ctype.h>
#include <numa.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#ifdef __STDC_NO_ATOMICS__
#error "The used complier or libc do not support atomic numbers"
#else
#include <stdatomic.h>
#endif

#include "dlog.h"
#include "ctypes.h"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#define DQDK_RCV_POLL (1 << 0)
#define DQDK_RCV_RTC (1 << 1)
#define IS_THREADED(nbqs) (nbqs != 1)
#define DQDK_DURATION 3

#define is_power_of_2(x) ((x != 0) && ((x & (x - 1)) == 0))
#define popcountl(x) __builtin_popcountl(x)
#define log2l(x) (31 - __builtin_clz(x))

struct xsk_stat {
    u64 rcvd_frames;
    u64 rcvd_pkts;
    u64 fail_polls;
    u64 timeout_polls;
    u64 rx_empty_polls;
    u64 rx_fill_fail_polls;
    u64 rx_successful_fills;
    u64 tx_successful_fills;
    u64 invalid_ip_pkts;
    u64 invalid_udp_pkts;
    u64 runtime;
    u64 tx_wakeup_sendtos;
    u64 sent_frames;
    u64 tristan_outoforder;
    u64 tristan_dups;
    u64 tristan_histogram_evts;
    u64 tristan_histogram_lost_evts;
    struct xdp_statistics xstats;
};

typedef struct {
    struct xsk_umem* umem;
    struct xsk_ring_prod fq0;
    struct xsk_ring_cons cq0;
    u32 size;
    void* buffer;
    u8 flags;
} umem_info_t;

typedef struct {
    u16 index;
    u16 queue_id;
    struct xsk_socket* socket;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    umem_info_t* umem_info;
    u32 libbpf_flags;
    u32 xdp_flags;
    u16 bind_flags;
    u32 batch_size;
    u8 busy_poll;
    struct xsk_stat stats;
    void* private;
    u8 debug;
} xsk_info_t;

#endif
