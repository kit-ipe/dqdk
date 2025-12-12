#ifndef TRISTAN_H
#define TRISTAN_H

#include <stdatomic.h>

#include "dqdk.h"
#include "dqdk-async-processor.h"
#include "ds/bhisto.h"
#include "ds/cne_ring.h"

#define TRISTAN_FE_PORT 5000
#define RINGBUFSZ (100ULL * 1024 * 1024 * 1024)
#define CONTROLLER_PORT 9001

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

#define HISTOBINS_COUNT (2 << 23) // = 2 ^ 24 values
#define HISTOBUCKETSZ (2 << 7)
#define HISTO_COUNT 6
#define TILECHNLS_COUNT 168
#define TILES_COUNT 9
#define CHNLS_COUNT (TILECHNLS_COUNT * TILES_COUNT)

typedef enum {
    TRISTAN_MODE_WAVEFORM,
    TRISTAN_MODE_LISTWAVE,
    TRISTAN_MODE_ENERGYHISTO,
} tristan_mode_t;

extern char* tristan_modes[];

typedef struct {
    bhisto_t* histograms[HISTO_COUNT];
} chnl_t;

typedef struct {
    chnl_t channels[CHNLS_COUNT];
} tristan_histo_t;

typedef struct {
    tristan_mode_t mode;
    _Atomic(u64) total_events;
    _Atomic(u64) total_bytes;
    char base_path[PATH_MAX];
    dqdk_async_processor_t* consumer;
    u8 strip_wfm;
    tristan_histo_t* histo;
    int rawdata_fd;
    int histo_fd;
    struct tm* timestamp;
    u32 payloadsz;
} tristan_t;

#define TRISTAN_HISTO_SZ (sizeof(tristan_histo_t))

#endif
