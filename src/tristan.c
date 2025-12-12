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

        posix_fadvise(private->rawdata_fd, 0, 0, POSIX_FADV_SEQUENTIAL);
        posix_fadvise(private->rawdata_fd, 0, 0, POSIX_FADV_DONTNEED);
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
        posix_fadvise(private->rawdata_fd, 0, 0, POSIX_FADV_DONTNEED);
    } else
        private->histo_fd = -1;

    private->consumer = dqdk_async_processor_init(ctx, 1, private, async_processor);
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

    if (dqdk_controller_closed(controller, buffer) < 0)
        dlog_error("Error sending closed status");

    free(buffer);

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

static dqdk_always_inline int tristan_process(dqdk_async_processor_t* proc, tristan_t* private, u8* buffer, u32 len, u32 burst)
{
    // Fetch from ring
    int ret = 0;
    burst = dqdk_async_processor_nfetch(proc, buffer, private->payloadsz, burst);
    if (!burst)
        return -ENOENT;

    u32 nbEvents = private->mode == TRISTAN_MODE_ENERGYHISTO ? private->payloadsz / TRISTAN_HISTO_EVT_SZ : 1;
    for (u32 i = 0; i < burst; i++) {
        // Compute histogram in listwave, listmode, and energy histogram
        if (private->histo_fd > 0) {
            tristan_energy_evt_t* evt = (tristan_energy_evt_t*)buffer;
            for (u32 e = 0; e < nbEvents; e++)
                histogram_event(private->histo, &evt[e]);
        }
    }

    if (private->rawdata_fd >= 0) {
        ret = write(private->rawdata_fd, buffer, len * burst);
        if (ret < 0) {
            dlog_error2("write", ret);
            return -errno;
        }
    }

    // Write to binary
    atomic_fetch_add_explicit(&private->total_bytes, len * burst, memory_order_relaxed);
    atomic_fetch_add_explicit(&private->total_events, nbEvents, memory_order_relaxed);
    return 0;
}

static void* async_processor(dqdk_async_processor_t* proc, void* private)
{
#define BLOCKSZ (2 << 20)
    int ret = 0, burst = 1;
    tristan_t* tristan = (tristan_t*)private;
    u8* buffer = (u8*)malloc(BLOCKSZ * 2 / tristan->payloadsz);
    u8* buffer_start = buffer;
    time_t t0 = time(NULL), t1;
    u64 rate = 0;

    if (!buffer)
        return NULL;

    u32 len = tristan->strip_wfm ? TRISTAN_HISTO_EVT_SZ : tristan->payloadsz;
    while (!dqdk_async_processor_has_stopped(proc)) {
        ret = tristan_process(proc, tristan, buffer, len, burst);
        if (ret == -ENOSPC)
            goto exit;

        if (ret)
            continue;

        rate++;
        t1 = time(NULL);
        if (t1 - t0 >= 1) {
            printf("Processed %llu/%lusec\n", rate, t1 - t0);
            t0 = t1;
            rate = 0;
        }
    }

    // Empty ring
    while (!dqdk_async_processor_isempty(proc)) {
        ret = tristan_process(proc, tristan, buffer, len, burst);
        if (ret == -ENOSPC)
            goto exit;

        if (ret)
            continue;

        rate++;
        t1 = time(NULL);
        if (t1 - t0 >= 1) {
            printf("Processed %llu/%lusec\n", rate, t1 - t0);
            t0 = t1;
            rate = 0;
        }
    }

exit:
    free(buffer_start);
    return (void*)(long)ret;
}

void tristan_usage(char* program)
{
    printf("Usage: %s -i <interface_name> -q <hardware_queue_id>\n", program);
    printf("Arguments:\n");
    printf("    -a <ports-range>             Accept source ports range e.g. 5000-5002 will reject all ports 3 ports 5000, 5001 & 5002,\n");
    printf("    -i <interface>               Set NIC to work on\n");
    printf("    -q <qid[-qid]>               Set range of hardware queues to work on e.g. -q 1 or -q 1-3.\n");
    printf("                                 Specifying multiple queues will launch a thread for each queue except if -p poll\n");
    printf("    -v                           Verbose\n");
    printf("    -b <size>                    Set batch size. Default: 64\n");
    printf("    -w                           Use XDP need wakeup flag\n");
    printf("    -s                           Expected Payload Size. Default: 3392\n");
    printf("    -l                           Dump latency values as a CSV file. Requires -D\n");
    printf("    -m <mode>                    Set TRISTAN Mode: waveform|listwave|energy-histo\n");
    printf("    -A <irq1,irq2,...>           Set affinity mapping between application threads and drivers queues\n");
    printf("                                 e.g. q1 to irq1, q2 to irq2,...\n");
    printf("    -B                           Enable NAPI busy-poll\n");
    printf("    -H                           Considering Hyper-threading is enabled, this flag will assign affinity\n");
    printf("                                 of softirq and the app to two logical cores of the same physical core.\n");
    printf("    -G                           Activate Huge Pages for UMEM allocation\n");
    printf("    -S                           Run IRQ and App on same core\n");
    printf("    -D                           Enable Latency measurements\n");
    printf("    -P                           Base Directory to Save TRISTAN Files\n");
    printf("    -W                           Strip Waveform in ListWave Mode\n");
}

int main(int argc, char** argv)
{
    // options values
    char* opt_ifname = NULL;
    char basedir[PATH_MAX] = { 0 };
    u32 opt_batchsize = 64, opt_queues[MAX_QUEUES], opt_irqs[MAX_QUEUES];
    u8 opt_umem_flags = 0, opt_stripwfm = 0;
    u32 opt_payloadsz = 3392;
    dqdk_ctx_opt_t opts = {
        .busypoll = 0,
        .debug = 0,
        .hyperthreading = 0,
        .irqworker_samecore = 0,
        .needs_wakeup = 0,
        .xdp_mode = XDP_MODE_NATIVE
    };

    // program variables
    tristan_t private = { .mode = TRISTAN_MODE_WAVEFORM };
    int opt;
    u32 nbqueues = 0, nbirqs = 0;

    dqdk_ctx_t* ctx = NULL;
    u16 start_port = 0, end_port = 0;
    dqdk_controller_t* controller = NULL;

    if (argc == 1) {
        tristan_usage(argv[0]);
        return 0;
    }

    memset(&private, 0, sizeof(private));
    memset(opt_queues, -1, sizeof(u32) * MAX_QUEUES);
    memset(opt_irqs, -1, sizeof(u32) * MAX_QUEUES);

    while ((opt = getopt(argc, argv, "a:b:hi:q:ws:lm:A:BDHGSP:W")) != -1) {
        switch (opt) {
        case 'h':
            tristan_usage(argv[0]);
            return 0;
        case 'a':
            char* delimiter = NULL;
            start_port = strtol(optarg, &delimiter, 10);
            if (delimiter != optarg) {
                end_port = strtol(++delimiter, &delimiter, 10);
            } else {
                dlog_error("Invalid port range.");
                exit(EXIT_FAILURE);
            }
            break;
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
        case 'i':
            opt_ifname = optarg;
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

                for (u32 idx = 0; idx < nbqueues; ++idx)
                    opt_queues[idx] = start + idx;
            }
            break;
        case 's':
            opt_payloadsz = atoi(optarg);
            break;
        case 'b':
            opt_batchsize = atoi(optarg);
            break;
        case 'w':
            opts.needs_wakeup = 1;
            break;
        case 'B':
            opts.busypoll = 1;
            break;
        case 'H':
            opts.hyperthreading = 1;
            break;
        case 'G':
            opt_umem_flags |= UMEM_FLAGS_USE_HGPG;
            break;
        case 'S':
            opts.irqworker_samecore = 1;
            break;
        case 'm':
            if (strcmp(optarg, tristan_modes[TRISTAN_MODE_ENERGYHISTO]) == 0)
                private.mode = TRISTAN_MODE_ENERGYHISTO;
            else if (strcmp(optarg, tristan_modes[TRISTAN_MODE_WAVEFORM]) == 0)
                private.mode = TRISTAN_MODE_WAVEFORM;
            else if (strcmp(optarg, tristan_modes[TRISTAN_MODE_LISTWAVE]) == 0)
                private.mode = TRISTAN_MODE_LISTWAVE;
            else {
                dlog_errorv("Unknown TRISTAN mode: %s", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'D':
            opts.debug |= DQDK_DEBUG;
            break;
        case 'l':
            opts.debug |= DQDK_DEBUG_LATENCYDUMP;
            break;
        case 'P':
            strncpy(basedir, optarg, PATH_MAX - 1);
            break;
        case 'W':
            opt_stripwfm = 1;
            break;
        default:
            tristan_usage(argv[0]);
            dlog_error("Invalid Arg\n");
            exit(EXIT_FAILURE);
        }
    }

    dlog_info("Waiting for Control Software to connect...");
    controller = dqdk_controller_start(CONTROLLER_PORT);
    if (controller == NULL)
        goto cleanup;

    dqdk_controller_report_status(controller, DQDK_STATUS_STARTED, NULL);

    ctx = dqdk_ctx_init(opt_ifname, opt_queues, nbqueues, opt_umem_flags, UMEM_SIZE,
        opt_batchsize, opt_payloadsz, RINGBUFSZ, &opts);

    if (!ctx) {
        dlog_info("Error Initializing DQDK Context");
        dqdk_controller_error(controller);
        goto cleanup;
    }

    if (opt_stripwfm && private.mode != TRISTAN_MODE_LISTWAVE) {
        dlog_error("Stripping Waveform is only available in ListWave mode");
        dqdk_controller_error(controller);
        goto cleanup;
    }

    dqdk_for_ports_range(ctx, start_port, end_port);

    if (tristan_init(ctx, &private, basedir, opt_stripwfm) < 0) {
        dqdk_controller_error(controller);
        goto cleanup;
    }

    for (u32 i = 0; i < nbqueues; i++) {
        if (dqdk_worker_init(ctx, opt_queues[i], opt_irqs[i]) < 0) {
            dqdk_controller_error(controller);
            goto cleanup;
        }
    }

    if (dqdk_start(ctx) < 0) {
        dlog_error("Error starting DQDK");
        dqdk_controller_error(controller);
        goto cleanup;
    }
    dqdk_controller_report_status(controller, DQDK_STATUS_READY, NULL);
    dlog_infov("TRISTAN DAQ in mode %s Started!", tristan_modes[private.mode]);

    int ret = dqdk_controller_wait(controller);
    // FIXME: in case the connection closed we need to run some timer and close after that
    if (ret < 0)
        goto cleanup;

    dlog_info("Closing...");

    if (dqdk_waitall(ctx) < 0)
        dqdk_controller_error(controller);

cleanup:
    tristan_fini(ctx, controller, &private);
    dqdk_dump_stats(ctx);
    dqdk_controller_free(controller);
    return dqdk_ctx_fini(ctx);
}