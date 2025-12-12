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
#include <linux/if_xdp.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#ifdef __STDC_NO_ATOMICS__
#error "The used complier or libc do not support atomic numbers"
#else
#include <stdatomic.h>
#endif

#include "dlog.h"
#include "ctypes.h"
#include "dqdk-sys.h"
#include "ds/cne_ring.h"
#include "dqdk-controller.h"

#define UMEM_FACTOR 64
#define UMEM_LEN (XSK_RING_PROD__DEFAULT_NUM_DESCS * UMEM_FACTOR)
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define UMEM_SIZE (UMEM_LEN * FRAME_SIZE)
#define UMEM_FLAGS_USE_HGPG (1 << 0)
#define UMEM_FLAGS_UNALIGNED (1 << 1)

#define MAX_QUEUES 16
#define DQDK_MAX_LATENCY_METRICS 10000000

typedef struct {
    u32 raw_idx;
    s64* raw;
    u64 sum;
    s64 min;
    s64 max;
} latency_t;

typedef struct {
    u64 rcvd_frames;
    u64 rcvd_pkts;
    u64 rcvd_bytes;
    u64 failing_batches;
    u64 fail_polls;
    u64 timeout_polls;
    u64 rx_empty_polls;
    u64 rx_fill_fail_polls;
    u64 rx_successful_fills;
    u64 invalid_ip_pkts;
    u64 invalid_udp_pkts;
    u64 runtime;
    latency_t queuing_latency;
    latency_t processing_latency;
    struct xdp_statistics xstats;
} dqdk_stats_t;

typedef struct {
    struct xsk_umem* umem;
    struct xsk_ring_prod fq0;
    struct xsk_ring_cons cq0;
    u64 size;
    void* buffer;
    u8 flags;
} umem_info_t;

enum {
    DQDK_DEBUG = 1 << 0,
    DQDK_DEBUG_LATENCYDUMP = 1 << 1,
};

typedef struct {
    pthread_t thread;
    pthread_attr_t* thread_attrs;
    u16 index;
    u16 queue_id;
    struct xsk_socket* socket;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    umem_info_t* umem_info;
    dqdk_stats_t stats;
    cpu_set_t cset;
    u32 batch_size;
    u8 busy_poll;
    u8 debug_flags;
    u64 soft_timestamp;
    cne_ring_t* ring;
} dqdk_worker_t;

typedef struct {
    u8 needs_wakeup;
    u8 busypoll;
    enum xdp_attach_mode xdp_mode;
    u8 irqworker_samecore;
    u8 debug;
    u8 hyperthreading;
} dqdk_ctx_opt_t;

typedef struct {
    pthread_barrier_t barrier;
    bool barrier_init;
    u32 queues[MAX_QUEUES];
    u32 nbqueues;
    dqdk_worker_t** workers;
    u8 umem_flags;
    u64 umem_size;
    u32 batch_size;
    u8 needs_wakeup;
    u8 busy_poll;
    u32 libbpf_flags;
    u32 bind_flags;
    u32 xdp_flags;
    u8 debug_flags;
    u8 hyperthreading;
    u8 samecore;
    u8 verbose;
    u32 payloadsz;
    char* ifname;
    int ifindex;
    int ifspeed;
    int numa_node;
    struct forwarder* forwarder;
    int xmode;
    unsigned long cpu_mask;
    int nbports;
    int huge_allocations;
    cne_ring_t* ring;
    u8* ring_buffer;
    u64 ringsz;
} dqdk_ctx_t;

dqdk_ctx_t* dqdk_ctx_init(char* ifname, u32 queues[], u32 nbqueues, u8 umem_flags, u64 umem_size, u32 batch_size, u32 payloadsz, u64 ringsz, dqdk_ctx_opt_t* opts);
int dqdk_for_ports_range(dqdk_ctx_t* ctx, u16 start, u16 end);
int dqdk_stats_dump(dqdk_ctx_t* ctx);
int dqdk_start(dqdk_ctx_t* ctx);
int dqdk_waitall(dqdk_ctx_t* ctx);
int dqdk_worker_init(dqdk_ctx_t* ctx, int qid, int irq);
dqdk_stats_t* dqdk_worker_stats(dqdk_ctx_t* ctx, u32 worker_index);
int dqdk_ctx_fini(dqdk_ctx_t*);
void dqdk_dump_stats(dqdk_ctx_t* ctx);
u8* dqdk_huge_malloc(dqdk_ctx_t* ctx, u64 size, page_size_t pagesz);
u8* dqdk_malloc(dqdk_ctx_t* ctx, u64 size, int flags);
int dqdk_free(dqdk_ctx_t* ctx, u8* mem, u64 size);
int dqdk_uses_hugepages(dqdk_ctx_t* ctx);
u32 dqdk_workers_count(dqdk_ctx_t* ctx);
#endif
