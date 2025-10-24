#ifndef TRISTAN_H
#define TRISTAN_H

#include <stdatomic.h>
#include "dqdk.h"
#include "dqdk-async-processor.h"

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

extern char* tristan_modes[];

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
    u64 max_bulk_size;
} tristan_histogram_private_t;

typedef struct {
    u8* bulk;
    u8* head;
    u64 max_bulk_size;
    tristan_mode_t mode;
    tristan_perthread_private_t** perthread_privates;
    dqdk_async_processor_t* async_histogrammer;
    dqdk_async_processor_t* async_writer;
    tristan_histogram_private_t* histo_private;
} tristan_private_t;

#define TRISTAN_HISTO_SZ (sizeof(tristan_histo_t))

int tristan_init(dqdk_ctx_t* ctx, tristan_private_t* private, tristan_mode_t mode, u64 bulksz);
int tristan_fini(dqdk_ctx_t* ctx, dqdk_controller_t* controller, tristan_private_t* private, double duration);
dqdk_always_inline int tristan_daq_waveform(tristan_private_t* private, dqdk_worker_t* xsk, u8* data, int datalen);
dqdk_always_inline int tristan_daq_listwave(tristan_private_t* private, dqdk_worker_t* xsk, u8* data, int datalen);
dqdk_always_inline int tristan_daq_energyhisto(tristan_private_t* private, dqdk_worker_t* xsk, u8* data, int datalen);

#endif
