#include <stdatomic.h>
#include <time.h>

#include "dqdk.h"
#include "dqdk-controller.h"
#include "dqdk-blk.h"
#include "dqdk-async-processor.h"
#include "dqdk-sys.h"
#include "tcpip/udp.h"
#include "tristan.h"

static void* async_histogrammer(void* private);
static void* async_writer(void* private);

char* tristan_modes[] = {
    [TRISTAN_MODE_DROP] = "drop",
    [TRISTAN_MODE_TLB] = "tlb",
    [TRISTAN_MODE_WAVEFORM] = "waveform",
    [TRISTAN_MODE_LISTWAVE] = "listwave",
    [TRISTAN_MODE_ENERGYHISTO] = "energy-histo",
};

int tristan_init(dqdk_ctx_t* ctx, tristan_private_t* private, tristan_mode_t mode, u64 bulksz, char* basedir, u8 strip_wfm)
{
    private->mode = mode;
    private->strip_wfm = strip_wfm;
    if (mode != TRISTAN_MODE_DROP) {
        dlog_info("Allocating TRISTAN Memory...");
        private->async_histogrammer = NULL;
        private->perthread_privates = calloc(dqdk_workers_count(ctx), sizeof(tristan_perthread_private_t*));
        if (private->perthread_privates == NULL)
            return -1;

        for (u32 i = 0; i < dqdk_workers_count(ctx); i++) {
            private->perthread_privates[i] = calloc(1, sizeof(tristan_perthread_private_t));
            if (private->perthread_privates[i] == NULL)
                return -1;
        }

        if (basedir == NULL || strnlen(basedir, PATH_MAX) == 0) {
            char* cwd = getcwd(private->base_path, PATH_MAX);
            if (!cwd) {
                dlog_error2("getcwd", !!cwd);
            }
        } else
            strncpy(private->base_path, basedir, PATH_MAX - 1);
        dlog_infov("Saving output files (if any) in %s.", private->base_path);

        if (mode == TRISTAN_MODE_WAVEFORM
            || mode == TRISTAN_MODE_LISTWAVE
            || mode == TRISTAN_MODE_ENERGYHISTO) {
            private->max_bulk_size = bulksz;
            private->bulk = dqdk_uses_hugepages(ctx) ? dqdk_huge_malloc(ctx, private->max_bulk_size, PAGE_2MB) : dqdk_malloc(ctx, private->max_bulk_size, 0);
            atomic_init(&private->head, private->bulk);

            if (private->bulk == NULL) {
                dlog_error("Error allocating huge pages memory for TRISTAN memory");
                return -1;
            }

            dlog_infov("Allocated %llu-Bytes for TRISTAN bulk data!", bulksz);
            private->async_writer = dqdk_async_processor_init(1, private, async_writer);
            if (!private->async_writer) {
                dlog_error("Error initializing async writer");
                return -1;
            }
        }

        if (mode == TRISTAN_MODE_ENERGYHISTO || mode == TRISTAN_MODE_LISTWAVE) {
            private->histo_private = (tristan_histogram_private_t*)calloc(1, sizeof(tristan_histogram_private_t));
            if (!private->histo_private) {
                dlog_error("Error allocating memory for histogram async processors");
                return -1;
            }

            strncpy(private->histo_private->base_path, private->base_path, PATH_MAX);
            private->histo_private->histo = (tristan_histo_t*)malloc(sizeof(tristan_histo_t));
            for (size_t channel = 0; channel < CHNLS_COUNT; channel++) {
                for (size_t h = 0; h < HISTO_COUNT; h++) {
                    private->histo_private->histo->channels[channel].histograms[h] = bhisto(HISTOBUCKETSZ, HISTOBINS_COUNT);
                    if (!private->histo_private->histo->channels[channel].histograms[h])
                        return -1;
                }
            }

            if (private->histo_private->histo == NULL) {
                dlog_error("Error allocating memory for TRISTAN histograms");
                return -1;
            }

            private->histo_private->skip_bytes = mode == TRISTAN_MODE_ENERGYHISTO || private->strip_wfm ? TRISTAN_HISTO_EVT_SZ : ctx->payloadsz;
            private->histo_private->head = private->bulk;
            private->histo_private->bulk = private->bulk;
            private->histo_private->max_bulk_size = private->max_bulk_size;
            private->async_histogrammer = dqdk_async_processor_init(1, private->histo_private, async_histogrammer);
            if (!private->async_histogrammer) {
                dlog_error("Error initializing histogram async processor");
                return -1;
            }
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
                stats.total_events += private->perthread_privates[i]->total_events;
                stats.total_bytes += private->perthread_privates[i]->total_bytes;
                if (wstats) {
                    stats.total_packets += wstats->rcvd_pkts;
                    stats.dqdk_runtime = MAX(stats.dqdk_runtime, wstats->runtime);
                }
            }
            stats.runtime = duration;

            buffer = calloc(8192, sizeof(char));
            snprintf(buffer, 8192,
                "{ \"total_received_events\": %llu,\"total_received_bytes\": %llu, \"total_received_packets\": %llu, \"dqdk_runtime_ms\": %.2lf, \"runtime_ms\": %.2lf, \"directory\": \"%s\"}",
                stats.total_events, stats.total_bytes, stats.total_packets,
                stats.dqdk_runtime / 1e6, stats.runtime, private->base_path);
        }

        dlog_info("Waiting for Async Writer to finish");
        dqdk_async_processor_cancel(private->async_writer);
        dlog_info("Waiting for Async Histogrammer to finish");
        dqdk_async_processor_cancel(private->async_histogrammer);

        if (dqdk_controller_closed(controller, buffer) < 0)
            dlog_error("Error sending closed status");

        free(buffer);
    }

    if (private->bulk != NULL)
        dqdk_free(ctx, private->bulk, private->max_bulk_size);

    if (private->histo_private) {
        if (private->histo_private->histo) {
            for (size_t channel = 0; channel < CHNLS_COUNT; channel++) {
                for (size_t h = 0; h < HISTO_COUNT; h++)
                    bhisto_free(private->histo_private->histo->channels[channel].histograms[h]);
            }
        }
        free(private->histo_private->histo);
        free(private->histo_private);
    }

    if (private->perthread_privates != NULL) {
        for (u32 i = 0; i < dqdk_workers_count(ctx); i++) {
            if (private->perthread_privates[i])
                free(private->perthread_privates[i]);
        }

        free(private->perthread_privates);
    }

    return 0;
}

static int tristan_buffer(tristan_private_t* private, dqdk_worker_t* xsk, u8* data, u32 datalen, u32 nbEvents)
{
    u32 copylen = private->strip_wfm ? TRISTAN_HISTO_EVT_SZ : datalen;
    u8* head = atomic_fetch_add_explicit(&private->head, copylen, memory_order_relaxed);
    if (head + copylen >= (private->bulk + private->max_bulk_size))
        return -1;

    memcpy(head, data, copylen);

    private->perthread_privates[xsk->index]->total_events += nbEvents;
    private->perthread_privates[xsk->index]->total_bytes += copylen;

    return 0;
}

dqdk_always_inline int tristan_daq_waveform(tristan_private_t* private, dqdk_worker_t* xsk, u8* data, u32 datalen)
{
    return tristan_buffer(private, xsk, data, datalen, 1);
}

dqdk_always_inline int tristan_daq_listwave(tristan_private_t* private, dqdk_worker_t* xsk, u8* data, u32 datalen)
{
    return tristan_buffer(private, xsk, data, datalen, 1);
}

dqdk_always_inline int tristan_daq_energyhisto(tristan_private_t* private, dqdk_worker_t* xsk, u8* data, u32 datalen)
{
    u32 nbevts = datalen / TRISTAN_HISTO_EVT_SZ;
    return tristan_buffer(private, xsk, data, datalen, nbevts);
}

static int histogram_event(tristan_histogram_private_t* private, tristan_energy_evt_t* evt)
{
    int histo_idx = log2l(evt->mask);
    if (evt->channel >= CHNLS_COUNT
        || histo_idx >= HISTO_COUNT
        || evt->energy >= HISTOBINS_COUNT) {
        dlog_errorv("Out of bounds Energy Event: Channel ID=%u, Histogram Index=%u, Energy=%u", evt->channel, histo_idx, evt->energy);
        return 0;
    }

    if (bhisto_increment(private->histo->channels[evt->channel].histograms[histo_idx], evt->energy) < 0)
        dlog_errorv("bhisto_increment failed. Channel=%d, Histogram=%d, Bin=%d", evt->channel, histo_idx, evt->energy);

    return 0;
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

static int write_csv_histograms(tristan_histo_t* histo, const char* path)
{
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    const char* header = "Channel,Histo,Energy,Freq\n";
    int len = strlen(header);
    int ret = write(fd, header, len);

    if (ret != len) {
        dlog_error2("write", 2);
        return -1;
    }

    for (int channel = 0; channel < CHNLS_COUNT; channel++) {
        for (int hidx = 0; hidx < HISTO_COUNT; hidx++) {
            if (bhisto_csv_dump(histo->channels[channel].histograms[hidx], fd, channel, hidx) < 0)
                dlog_errorv("Error writing histogram %d in channel %d", hidx, channel);
        }
    }

    if (fsync(fd) || close(fd)) {
        dlog_errorv("Error while closing file: %s", path);
        return -1;
    }

    return 0;
}

static void* async_histogrammer(void* arg)
{
    int break_flag = 0;
    tristan_energy_evt_t zevent = { 0 };
    dqdk_async_processor_t* proc = (dqdk_async_processor_t*)arg;
    tristan_histogram_private_t* histo = (tristan_histogram_private_t*)proc->private;
    while (!dqdk_async_processor_has_stopped(proc) && !break_flag) {
        while (memcmp(histo->head, &zevent, sizeof(zevent))) {
            tristan_energy_evt_t* evt = (tristan_energy_evt_t*)histo->head;
            if (!histogram_event(histo, evt))
                histo->head += histo->skip_bytes;
            else {
                break_flag = 1;
                break;
            }
        }
    }

    if (histo && histo->histo) {
        char path_name[8192] = { 0 };
        struct tm* local = getlocaltime();
        dlog_info("Saving TRISTAN Histogram, this may take a while...");
        snprintf(path_name, sizeof(path_name), "%s/tristan-histo-%04d-%02d-%02d-%02d-%02d-%02d.csv",
            histo->base_path, local->tm_year + 1900, local->tm_mon + 1,
            local->tm_mday, local->tm_hour, local->tm_min, local->tm_sec);
        if (histo->head != histo->bulk) {
            int ret = write_csv_histograms(histo->histo, path_name);
            if (ret)
                dlog_infov("write_csv_histograms returned %d\n", ret);
        }
    }
    dlog_info("Async Histogrammer has exited");
    return NULL;
}

static s64 write_available_blocks(tristan_private_t* private, int fd, u32 blocksz, u8** writer_head)
{
    ssize_t ret = 0;
    s64 available_bytes = atomic_load_explicit(&private->head, memory_order_relaxed) - *writer_head;
    s64 total_wr = 0;
    while (total_wr != available_bytes) {
        int wr_bytes = (available_bytes - total_wr) >= blocksz ? blocksz : (available_bytes - total_wr);

        ret = write(fd, *writer_head, wr_bytes);
        if (ret < 0) {
            total_wr = -errno;
            printf("write failed with %d\n", errno);
            break;
        }

        total_wr += ret;
        *writer_head += ret;
    }

    return total_wr;
}

static void* async_writer(void* arg)
{
    u64 total_wr = 0;
    s64 ret = 0;
    dqdk_async_processor_t* proc = (dqdk_async_processor_t*)arg;
    tristan_private_t* private = (tristan_private_t*)proc->private;
    u32 blocksz = FILE_BSIZE;

    if (private->mode == TRISTAN_MODE_DROP || private->mode == TRISTAN_MODE_TLB) {
        dlog_info("Modes: TRISTAN_MODE_DROP and TRISTAN_MODE_TLB do not save to disk");
        goto exit;
    }

    if (!private->bulk) {
        dlog_error("Invalid bulk object to save");
        goto exit;
    }

    struct tm* tm = getlocaltime();
    char path[8192] = { 0 };
    snprintf(path, sizeof(path), "%s/tristan-%s-%04d-%02d-%02d-%02d-%02d-%02d.bin",
        private->base_path, tristan_modes[private->mode], tm->tm_year + 1900,
        tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);

    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        ret = -errno;
        goto exit;
    }

    u8* writer_head = private->bulk;
    while (!dqdk_async_processor_has_stopped(proc)) {
        ret = write_available_blocks(private, fd, blocksz, &writer_head);
        if (ret < 0)
            goto exit;
        else
            total_wr += ret;
    }

    ret = write_available_blocks(private, fd, blocksz, &writer_head);
    if (ret < 0)
        goto exit;
    else
        total_wr += ret;

    if (fsync(fd) < 0 || close(fd) < 0)
        ret = -errno;

exit:
    if (!total_wr || ret < 0)
        remove(path);

    if (ret < 0)
        dlog_errorv("Error writing blocks for bulk data in async writer=%lld", ret);
    else
        dlog_infov("Saved TRISTAN Waveform (Total Bytes=%llu)", total_wr);

    return NULL;
}
