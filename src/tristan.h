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
} packed;

struct waveform {
    u16 id;
    u16 channel;
    u8 subcnt;
    u8 aux_info[3];
    u16 waveform;
} packed;

struct listwave {
    struct energy_evt energy;
    u16 waveform;
} packed;

typedef struct energy_evt energy_evt_t;
typedef struct waveform waveform_t;
typedef struct listwave listwave_t;

#define TRISTAN_HISTO_EVT_SZ sizeof(energy_evt_t)

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

typedef struct {
    u32 histograms[HISTO_COUNT][HISTO_BINS];
} chnl_t;

typedef struct {
    chnl_t channels[CHNLS_COUNT];
} tristan_histo_t;

typedef struct {
    tristan_histo_t* histo;
    u8* bulk;
    u8* head;
    u64 bulk_size;
    u64 max_bulk_size;
    tristan_mode_t mode;
} tristan_private_t;

#define TRISTAN_HISTO_SZ (sizeof(tristan_histo_t))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ntoh24b(x) (((x & 0xff) << 16) | (((x >> 8) & 0xff) << 8) | ((x >> 16) & 0xff))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ntoh24b(x) (x)
#else
#error "Unsupported Endianess"
#endif

static dqdk_always_inline int tristan_daq_waveform(tristan_private_t* private, dqdk_worker_t* xsk, u8* data, int datalen)
{
    (void)xsk;
    u8* head = atomic_fetch_add_explicit(&private->head, datalen, memory_order_relaxed);
    memcpy(head, data, datalen);

    return 0;
}

dqdk_always_inline int tristan_daq_energyhisto(tristan_private_t* private, dqdk_worker_t* xsk, u8* data, int datalen)
{
    energy_evt_t* evts = (energy_evt_t*)data;
    int nbevts = datalen / TRISTAN_HISTO_EVT_SZ;

    for (int i = 0; i < nbevts; i++) {
        energy_evt_t evt = evts[i];
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

    return 0;
}

#endif
