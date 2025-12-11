#include <stdatomic.h>
#include <time.h>

#include "dqdk.h"
#include "dqdk-controller.h"
#include "dqdk-blk.h"
#include "dqdk-async-processor.h"
#include "dqdk-sys.h"
#include "tcpip/udp.h"
#include "tristan.h"
#include "ds/cne_ring.h"

static void* async_processor(dqdk_async_processor_t* proc, void* tristan);

char* tristan_modes[] = {
    [TRISTAN_MODE_WAVEFORM] = "waveform",
    [TRISTAN_MODE_LISTWAVE] = "listwave",
    [TRISTAN_MODE_ENERGYHISTO] = "energy-histo",
};

static char* getrawfilename(tristan_t* tristan)
{
    struct tm* tm = tristan->timestamp;
    int buffersz = PATH_MAX * 2;

    char* path = calloc(buffersz, sizeof(char));
    snprintf(path, buffersz, "%s/tristan-%s-%04d-%02d-%02d-%02d-%02d-%02d.bin",
        tristan->base_path, tristan_modes[tristan->mode], tm->tm_year + 1900,
        tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);

    return path;
}

static char* gethistofilename(tristan_t* tristan)
{
    struct tm* tm = tristan->timestamp;
    int buffersz = PATH_MAX * 2;

    char* path = calloc(buffersz, sizeof(char));
    snprintf(path, buffersz, "%s/tristan-histo-%04d-%02d-%02d-%02d-%02d-%02d.csv",
        tristan->base_path, tm->tm_year + 1900, tm->tm_mon + 1,
        tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);

    return path;
}

struct csv_dumper_priv {
    int channel;
    int histo;
    int fd;
};

static int bhist_csv_dump_row(u32 energy, u32 freq, void* priv)
{
    if (!freq)
        return 0;

    struct csv_dumper_priv* meta = (struct csv_dumper_priv*)priv;
    return dprintf(meta->fd, "%d,%d,%u,%u\n", meta->channel, meta->histo, energy, freq);
}

int bhisto_csv_dump(bhisto_t* bhisto, int fd, int channel, int histo)
{
    if (!bhisto)
        return 0;

    struct csv_dumper_priv priv = { .channel = channel, .histo = histo, .fd = fd };
    return bhisto_iterate(bhisto, bhist_csv_dump_row, &priv);
}

int tristan_init(dqdk_ctx_t* ctx, tristan_t* private, char* basedir, u8 strip_wfm)
{
    int nbWorkers = 1;
    private->strip_wfm = strip_wfm;
    private->timestamp = getlocaltime();
    private->payloadsz = ctx->payloadsz;
    atomic_init(&private->total_bytes, 0);
    atomic_init(&private->total_events, 0);

    if (basedir == NULL || strnlen(basedir, PATH_MAX) == 0) {
        char* cwd = getcwd(private->base_path, PATH_MAX);
        if (!cwd) {
            dlog_error2("getcwd", !!cwd);
        }
    } else
        strncpy(private->base_path, basedir, PATH_MAX - 1);
    dlog_infov("Saving output files (if any) in %s.", private->base_path);

    if (private->mode == TRISTAN_MODE_WAVEFORM
        || private->mode == TRISTAN_MODE_LISTWAVE
        || private->mode == TRISTAN_MODE_ENERGYHISTO) {
        char* path = getrawfilename(private);
        private->rawdata_fd = open(path, O_CREAT | O_WRONLY, 0644);
        free(path);
        if (private->rawdata_fd < 0) {
            dlog_error2("open", private->rawdata_fd);
            return -errno;
        }
    } else
        private->rawdata_fd = -1;

    if (private->mode == TRISTAN_MODE_LISTWAVE
        || private->mode == TRISTAN_MODE_ENERGYHISTO) {
        char* path = gethistofilename(private);
        private->histo_fd = open(path, O_CREAT | O_WRONLY, 0644);
        free(path);
        if (private->histo_fd < 0) {
            dlog_error2("open", private->histo_fd);
            return -errno;
        }
    } else
        private->histo_fd = -1;

    private->consumer = dqdk_async_processor_init(ctx, nbWorkers, private, async_processor);
    if (!private->consumer) {
        dlog_error("Error initializing async consumers");
        return -1;
    }

    return 0;
}

int tristan_fini(dqdk_ctx_t* ctx, dqdk_controller_t* controller, tristan_t* private)
{
    int buffersz = 8192;

    dlog_info("Waiting for Async Consumer to finish");
    dqdk_async_processor_cancel(private->consumer);

    tristan_stats_t stats = {
        .total_bytes = atomic_load_explicit(&private->total_bytes, memory_order_relaxed),
        .total_events = atomic_load_explicit(&private->total_events, memory_order_relaxed)
    };

    for (u32 i = 0; i < dqdk_workers_count(ctx); i++) {
        dqdk_stats_t* wstats = dqdk_worker_stats(ctx, i);
        if (wstats) {
            stats.total_packets += wstats->rcvd_pkts;
            stats.dqdk_runtime = MAX(stats.dqdk_runtime, wstats->runtime);
        }
    }

    char* buffer = calloc(buffersz, sizeof(char));
    snprintf(buffer, buffersz,
        "{ \"total_received_events\": %llu,\"total_received_bytes\": %llu, \"total_received_packets\": %llu, \"dqdk_runtime_ms\": %.2lf, \"directory\": \"%s\"}",
        stats.total_events, stats.total_bytes, stats.total_packets,
        stats.dqdk_runtime / 1e6, private->base_path);

    if (dqdk_controller_closed(controller, buffer) < 0)
        dlog_error("Error sending closed status");

    free(buffer);

    dlog_info("Saving files...");
    if (private->rawdata_fd > 0) {
        if (fsync(private->rawdata_fd) < 0 || close(private->rawdata_fd) < 0)
            dlog_error("Failed to save and close files. Data may be missing");
    }

    if (private->histo_fd > 0) {
        const char* header = "Channel,Histo,Energy,Freq\n";
        int len = strlen(header);
        int ret = write(private->histo_fd, header, len);

        if (ret != len) {
            dlog_error2("write", 2);
            return -1;
        }

        for (int channel = 0; channel < CHNLS_COUNT; channel++) {
            for (int hidx = 0; hidx < HISTO_COUNT; hidx++) {
                if (bhisto_csv_dump(private->histo->channels[channel].histograms[hidx], private->histo_fd, channel, hidx) < 0)
                    dlog_errorv("Error writing histogram %d in channel %d", hidx, channel);
                bhisto_free(private->histo->channels[channel].histograms[hidx]);
            }
        }
        free(private->histo);

        if (fsync(private->histo_fd) || close(private->histo_fd))
            dlog_error("Error while closing histogram file");
    }

    return 0;
}

static int histogram_event(tristan_histo_t* histo, tristan_energy_evt_t* evt)
{
    int histo_idx = log2l(evt->mask);
    if (evt->channel >= CHNLS_COUNT
        || histo_idx >= HISTO_COUNT
        || evt->energy >= HISTOBINS_COUNT) {
        dlog_errorv("Out of bounds Energy Event: Channel ID=%u, Histogram Index=%u, Energy=%u", evt->channel, histo_idx, evt->energy);
        return -1;
    }

    if (bhisto_increment(histo->channels[evt->channel].histograms[histo_idx], evt->energy) < 0)
        dlog_errorv("bhisto_increment failed. Channel=%d, Histogram=%d, Bin=%d", evt->channel, histo_idx, evt->energy);

    return 0;
}

static dqdk_always_inline int tristan_process(dqdk_async_processor_t* proc, tristan_t* private, u8* buffer)
{
    // Fetch from ring
    int ret = dqdk_async_processor_fetch(proc, buffer, private->payloadsz);
    if (ret)
        return 0;

    u32 len = private->strip_wfm ? TRISTAN_HISTO_EVT_SZ : private->payloadsz;

    // Write to binary
    if (private->rawdata_fd >= 0) {
        ret = write(private->rawdata_fd, buffer, len);
        if (ret < 0) {
            dlog_error2("write", ret);
            return -errno;
        }
    }

    // Compute histogram in listwave, listmode, and energy histogram
    u32 nbEvents = private->mode == TRISTAN_MODE_ENERGYHISTO ? private->payloadsz / TRISTAN_HISTO_EVT_SZ : 1;
    if (private->histo_fd > 0) {
        tristan_energy_evt_t* evt = (tristan_energy_evt_t*)buffer;
        for (u32 i = 0; i < nbEvents; i++)
            histogram_event(private->histo, &evt[i]);
    }

    atomic_fetch_add_explicit(&private->total_bytes, len, memory_order_relaxed);
    atomic_fetch_add_explicit(&private->total_events, nbEvents, memory_order_relaxed);
    return 0;
}

static void* async_processor(dqdk_async_processor_t* proc, void* private)
{
    tristan_t* tristan = (tristan_t*)private;
    u8* buffer = (u8*)malloc(tristan->payloadsz);
    if (!buffer)
        return NULL;

    while (!dqdk_async_processor_has_stopped(proc)) {
        if (tristan_process(proc, tristan, buffer))
            continue;
    }

    // Empty ring
    while (!dqdk_async_processor_isempty(proc)) {
        if (tristan_process(proc, tristan, buffer))
            continue;
    }

    free(buffer);
    return NULL;
}
