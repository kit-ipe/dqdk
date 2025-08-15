#ifndef TRISTAN_H
#define TRISTAN_H

#include <stdatomic.h>
#include "dqdk.h"

#define TRISTAN_FE_PORT 5000

struct energy_evt {
    u16 id;
    u16 channel;
    u32 energy : 24;
    u8 mask;
    u16 trigger_info;
    u64 timestamp : 48;
} dqdk_packed;

typedef struct energy_evt tristan_energy_evt_t;

struct waveform {
    u16 id;
    u16 channel;
    u8 subcnt;
    u8 aux_info[3];
    u16 waveform[];
} dqdk_packed;

struct listwave {
    tristan_energy_evt_t energy;
    u16 waveform[];
} dqdk_packed;

typedef struct {
    u64 min_event_id;
    u64 max_event_id;
    u64 total_events;
    u64 total_packets;
    u64 total_bytes;
    u64 dqdk_runtime;
    double runtime;
} tristan_stats_t;

typedef struct waveform tristan_waveform_t;
typedef struct listwave tristan_listwave_t;

#define TRISTAN_HISTO_EVT_SZ sizeof(tristan_energy_evt_t)

#define HISTO_BINS (2 << 15) // 2^16 bins
#define HISTO_COUNT 8 // usually 5 or 6
#define CHNLS_1TILE 166
#define TILES_COUNT 9
#define CHNLS_COUNT (CHNLS_1TILE * TILES_COUNT)

typedef enum {
    TRISTAN_MODE_DROP,
    TRISTAN_MODE_TLB,
    TRISTAN_MODE_WAVEFORM,
    TRISTAN_MODE_LISTWAVE,
    TRISTAN_MODE_ENERGYHISTO,
} tristan_mode_t;

char* tristan_modes[] = {
    [TRISTAN_MODE_DROP] = "drop",
    [TRISTAN_MODE_TLB] = "tlb",
    [TRISTAN_MODE_WAVEFORM] = "waveform",
    [TRISTAN_MODE_LISTWAVE] = "listwave",
    [TRISTAN_MODE_ENERGYHISTO] = "energy-histo",
};

typedef struct {
    u32 histograms[HISTO_COUNT][HISTO_BINS];
} chnl_t;

typedef struct {
    chnl_t channels[CHNLS_COUNT];
} tristan_histo_t;

struct tristan_perthread_private {
    u64 min_event_id;
    u64 max_event_id;
    u64 total_events;
    u64 total_bytes;
} dqdk_cache_aligned;

typedef struct tristan_perthread_private tristan_perthread_private_t;

typedef struct {
    tristan_histo_t* histo;
    u8* bulk;
    u8* head;
    u64 bulk_size;
    u64 max_bulk_size;
    tristan_mode_t mode;
    tristan_perthread_private_t** perthread_privates;
} tristan_private_t;

#define TRISTAN_HISTO_SZ (sizeof(tristan_histo_t))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ntoh24b(x) (((x & 0xff) << 16) | (((x >> 8) & 0xff) << 8) | ((x >> 16) & 0xff))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ntoh24b(x) (x)
#else
#error "Unsupported Endianess"
#endif

int tristan_init(dqdk_ctx_t* ctx, tristan_private_t* private, tristan_mode_t mode, u64 bulksz)
{
    private->mode = mode;
    if (mode != TRISTAN_MODE_DROP) {
        dlog_info("Allocating TRISTAN Memory...");
        private->perthread_privates = calloc(dqdk_workers_count(ctx), sizeof(tristan_perthread_private_t*));
        if (private->perthread_privates == NULL)
            return -1;

        for (u32 i = 0; i < dqdk_workers_count(ctx); i++) {
            private->perthread_privates[i] = calloc(1, sizeof(tristan_perthread_private_t));
            if (private->perthread_privates[i] == NULL)
                return -1;
        }

        if (mode == TRISTAN_MODE_ENERGYHISTO) {
            if (dqdk_uses_hugepages(ctx))
            private->histo = (tristan_histo_t*)dqdk_huge_malloc(ctx, TRISTAN_HISTO_SZ, PAGE_2MB);
            else private->histo = (tristan_histo_t*)dqdk_malloc(ctx, TRISTAN_HISTO_SZ, 0);

            if (private->histo == NULL) {
                dlog_error("Error allocating huge pages memory for TRISTAN histograms");
                return -1;
            }
        }

        if (mode == TRISTAN_MODE_TLB
            || mode == TRISTAN_MODE_WAVEFORM
            || mode == TRISTAN_MODE_LISTWAVE) {
            private->max_bulk_size = bulksz;
            private->bulk = dqdk_uses_hugepages(ctx) ? dqdk_huge_malloc(ctx, private->max_bulk_size, PAGE_2MB) : dqdk_malloc(ctx, private->max_bulk_size, 0);
            private->head = private->bulk;
            private->bulk_size = 0;

            if (private->bulk == NULL) {
                dlog_error("Error allocating huge pages memory for TRISTAN memory");
                return -1;
            }
        }
    }

    return 0;
}

int tristan_save(tristan_private_t* private)
{
    if (private->mode != TRISTAN_MODE_DROP && private->mode != TRISTAN_MODE_TLB) {
        struct tm tm = { 0 };
        time_t tval = time(NULL);
        char path_name[PATH_MAX];

        if (tval != ((time_t)-1))
            tm = *localtime(&tval);

        if (private->histo) {
            dlog_info("Saving TRISTAN Histogram, this may take a while...");
            snprintf(path_name, PATH_MAX, "tristan-histo-%04d-%02d-%02d-%02d%02d.bin", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min);
            dqdk_blk_status_t stats = dqdk_blk_dump(path_name, FILE_BSIZE, TRISTAN_HISTO_SZ, private->histo);
            if (stats.status != 0)
                dlog_infov("DQDK-BLK Object dumping failed, returned %d\n", stats.status);
        }

        memset(path_name, 0, PATH_MAX);

        u64 bytes = private->head - private->bulk;
        if (private->bulk && bytes != 0) {
            dlog_infov("Saving TRISTAN Waveform (Total Bytes=%llu), this may take a while...", bytes);
            snprintf(path_name, PATH_MAX, "tristan-raw-%04d-%02d-%02d-%02d%02d.bin", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min);
            dqdk_blk_status_t stats = dqdk_blk_dump(path_name, FILE_BSIZE, bytes, private->bulk);
            if (stats.status != 0)
                dlog_infov("DQDK-BLK Object dumping failed, returned %d\n", stats.status);
        }
    }
    return 0;
}

int tristan_fini(dqdk_ctx_t* ctx, dqdk_controller_t* controller, tristan_private_t* private, double duration)
{
    if (private->mode != TRISTAN_MODE_DROP && private->mode != TRISTAN_MODE_TLB) {
        char* buffer = NULL;
        if (private->perthread_privates != NULL) {
            tristan_stats_t stats = { 0 };
            for (u32 i = 0; i < dqdk_workers_count(ctx); i++) {
                dqdk_stats_t* wstats = dqdk_worker_stats(ctx, i);
                stats.max_event_id = MAX(private->perthread_privates[i]->max_event_id, stats.max_event_id);
                stats.min_event_id = MAX(private->perthread_privates[i]->min_event_id, stats.min_event_id);
                stats.total_events += private->perthread_privates[i]->total_events;
                stats.total_bytes += private->perthread_privates[i]->total_bytes;
                stats.total_packets += wstats->rcvd_pkts;
                stats.dqdk_runtime = MAX(stats.dqdk_runtime, wstats->runtime);
            }
            stats.runtime = duration;

            buffer = calloc(1024, sizeof(char));
            snprintf(buffer, 1024,
                "{ \"max_event_id\": %llu, \"min_event_id\": %llu, \"total_events\": %llu,\"total_bytes\": %llu, \"total_packets\": %llu, \"dqdk_runtime\": %llu, \"runtime\": %lf }",
                stats.max_event_id, stats.min_event_id, stats.total_events,
                stats.total_bytes, stats.total_packets, stats.dqdk_runtime,
                stats.runtime);
        }

        if (dqdk_controller_closed(controller, buffer) < 0)
            dlog_error("Error sending closed status");

        free(buffer);
    }

    if (private->bulk != NULL)
        dqdk_free(ctx, private->bulk, private->max_bulk_size);

    if (private->histo != NULL)
        dqdk_free(ctx, (u8*)private->histo, TRISTAN_HISTO_SZ);

    if (private->perthread_privates != NULL) {
        for (u32 i = 0; i < dqdk_workers_count(ctx); i++) {
            if (private->perthread_privates[i])
                free(private->perthread_privates[i]);
        }

        free(private->perthread_privates);
    }

    return 0;
}

static dqdk_always_inline int tristan_daq_waveform(tristan_private_t* private, dqdk_worker_t* xsk, u8* data, int datalen)
{
    u8* head = atomic_fetch_add_explicit(&private->head, datalen, memory_order_relaxed);
    if (head + datalen >= (private->bulk + private->max_bulk_size)) {
        atomic_fetch_add_explicit(&private->head, -datalen, memory_order_relaxed);
        return -1;
    }

    memcpy(head, data, datalen);

    u16* waveform = (u16*)data;
    private->perthread_privates[xsk->index]->max_event_id = MAX(private->perthread_privates[xsk->index]->max_event_id, waveform[0]);
    private->perthread_privates[xsk->index]->min_event_id = MIN(private->perthread_privates[xsk->index]->min_event_id, waveform[0]);
    private->perthread_privates[xsk->index]->total_events++;
    private->perthread_privates[xsk->index]->total_bytes += datalen;

    return 0;
}

static dqdk_always_inline int tristan_daq_listwave(tristan_private_t* private, dqdk_worker_t* xsk, u8* data, int datalen)
{
    u8* head = atomic_fetch_add_explicit(&private->head, datalen, memory_order_relaxed);
    if (head + datalen >= (private->bulk + private->max_bulk_size)) {
        atomic_fetch_add_explicit(&private->head, -datalen, memory_order_relaxed);
        return -1;
    }

    memcpy(head, data, datalen);

    u16* listwave = (u16*)data;
    private->perthread_privates[xsk->index]->max_event_id = MAX(private->perthread_privates[xsk->index]->max_event_id, listwave[0]);
    private->perthread_privates[xsk->index]->min_event_id = MIN(private->perthread_privates[xsk->index]->min_event_id, listwave[0]);
    private->perthread_privates[xsk->index]->total_events++;
    private->perthread_privates[xsk->index]->total_bytes += datalen;

    return 0;
}

dqdk_always_inline int tristan_daq_energyhisto(tristan_private_t* private, dqdk_worker_t* xsk, u8* data, int datalen)
{
    tristan_energy_evt_t* evts = (tristan_energy_evt_t*)data;
    int nbevts = datalen / TRISTAN_HISTO_EVT_SZ;

    // TODO: can we SIMD this?
    for (int i = 0; i < nbevts; i++) {
        tristan_energy_evt_t evt = evts[i];
        if (xsk->debug_flags) {
            dlog_infov("Evnt %d: Energy=%u; TimeStamp=%llu; Channel=%d; Mask=%d\n", evt.id,
                evt.energy, (u64)evt.timestamp, evt.channel, evt.mask);
        }

        int histo_idx = log2l(evt.mask);
        if (evt.channel >= CHNLS_COUNT
            || histo_idx >= HISTO_COUNT
            || evt.energy >= HISTO_BINS) {
            dlog_errorv("Out of bounds Energy Event: Channel ID=%u, Histogram Index=%u, Energy=%u", evt.channel, histo_idx, evt.energy);
            return -1;
        }

        u32* counter = &private->histo->channels[evt.channel].histograms[histo_idx][evt.energy];
        atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);
    }

    // TODO: fix this
    // private->perthread_privates[xsk->index]->max_event_id = MAX(private->perthread_privates[xsk->index]->max_event_id, listwave->energy.id);
    // private->perthread_privates[xsk->index]->min_event_id = MIN(private->perthread_privates[xsk->index]->min_event_id, listwave->energy.id);
    private->perthread_privates[xsk->index]->total_events += nbevts;
    private->perthread_privates[xsk->index]->total_bytes += datalen;

    return 0;
}

#endif
