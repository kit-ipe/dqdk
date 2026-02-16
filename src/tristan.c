#include <stdatomic.h>
#include <time.h>

#include "dqdk.h"
#include "dqdk-controller.h"
#include "dqdk-blk.h"
#include "dqdk-async-processor.h"
#include "dqdk-sys.h"
#include "tristan.h"

static void* async_processor(dqdk_async_processor_t* proc, void* tristan);

char* tristan_modes[] = {
    [TRISTAN_MODE_WAVEFORM] = "waveform",
    [TRISTAN_MODE_LISTWAVE] = "listwave",
    [TRISTAN_MODE_LISTMODE] = "listmode",
    [TRISTAN_MODE_ENERGYHISTO] = "energy-histo",
};

static char* getrawfilename(tristan_t* tristan)
{
    struct tm* tm = tristan->timestamp;
    int buffersz = PATH_MAX * 2;

    char* path = calloc(buffersz, sizeof(char));
    snprintf(path, buffersz, "%s/tristan-be%d-%s-%04d-%02d-%02d-%02d-%02d-%02d.bin",
        tristan->base_path, tristan->id, tristan_modes[tristan->mode], tm->tm_year + 1900,
        tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);

    return path;
}

static char* gethistofilename(tristan_t* tristan)
{
    struct tm* tm = tristan->timestamp;
    int buffersz = PATH_MAX * 2;

    char* path = calloc(buffersz, sizeof(char));
    snprintf(path, buffersz, "%s/tristan-be%d-histo-%04d-%02d-%02d-%02d-%02d-%02d.csv",
        tristan->base_path, tristan->id, tm->tm_year + 1900, tm->tm_mon + 1,
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

static int is_store_raw(u64 ringsz, u32 payloadsz, char* ifname, tristan_mode_t mode, s64 duration)
{
    if (mode == TRISTAN_MODE_WAVEFORM)
        return 1;

    int ifspeed = dqdk_get_link_speed(ifname);
    if (ifspeed < 0)
        return -1;
    u64 count = dqdk_calc_ring_count(ringsz, payloadsz);
    ringsz = dqdk_calc_ring_size(count, payloadsz);
    return (mode == TRISTAN_MODE_LISTWAVE || mode == TRISTAN_MODE_LISTMODE) && duration < dqdk_calc_ring_msec_capacity(ringsz, ifspeed);
}

static int is_store_histo(tristan_mode_t mode)
{
    return mode == TRISTAN_MODE_LISTWAVE
        || mode == TRISTAN_MODE_LISTMODE
        || mode == TRISTAN_MODE_ENERGYHISTO;
}

static dqdk_always_inline u32 get_energy_events_count(tristan_mode_t mode, u32 payloadsz)
{
    switch (mode) {
    case TRISTAN_MODE_LISTMODE:
    case TRISTAN_MODE_ENERGYHISTO:
        return payloadsz / TRISTAN_HISTO_EVT_SZ;
    case TRISTAN_MODE_LISTWAVE:
    case TRISTAN_MODE_WAVEFORM:
        return 1;
    default:
        return 0;
    }
    return 0;
}

int tristan_init(dqdk_ctx_t* ctx, tristan_t* private, char* basedir, s64 duration, int id, u8 strip_wfm)
{
    private->strip_wfm = strip_wfm;
    private->timestamp = getlocaltime();
    private->payloadsz = ctx->payloadsz;
    private->duration = duration;
    private->rawdata_fd = -1;
    private->histo_fd = -1;
    private->id = id;

    private->histo = calloc(1, TRISTAN_HISTO_SZ);
    if (!private->histo) {
        dlog_error("No memory to allocate histograms");
        return -1;
    }

    atomic_init(&private->total_bytes, 0);
    atomic_init(&private->total_events, 0);

    if (private->mode == TRISTAN_MODE_WAVEFORM && duration >= dqdk_ring_msec_capacity(ctx)) {
        dlog_errorv("Too long DAQ duration in Waveform. Maximum DAQ capacity is %lf millisecond", dqdk_ring_msec_capacity(ctx));
        return -1;
    }

    if (basedir == NULL || strnlen(basedir, PATH_MAX) == 0) {
        char* cwd = getcwd(private->base_path, PATH_MAX);
        if (!cwd) {
            dlog_error2("getcwd", !!cwd);
            return -1;
        }
    } else
        strncpy(private->base_path, basedir, PATH_MAX - 1);
    dlog_infov("Saving output files (if any) in %s.", private->base_path);

    if (is_store_raw(ctx->ringsz, ctx->payloadsz, ctx->ifname, private->mode, private->duration) > 0) {
        char* path = getrawfilename(private);
        private->rawdata_fd = open(path, O_CREAT | O_WRONLY, 0644);
        dlog_infov("Raw File Path: %s", path);
        free(path);
        if (private->rawdata_fd < 0) {
            dlog_error2("open", private->rawdata_fd);
            return -errno;
        }

        posix_fadvise(private->rawdata_fd, 0, 0, POSIX_FADV_SEQUENTIAL);
        posix_fadvise(private->rawdata_fd, 0, 0, POSIX_FADV_DONTNEED);
    }

    if (is_store_histo(private->mode)) {
        for (int channel = 0; channel < CHNLS_COUNT; channel++) {
            for (int hidx = 0; hidx < CHANNELHISTO_COUNT; hidx++) {
                private->histo->channels[channel].histograms[hidx] = bhisto(HISTO_BUCKETSCOUNT, HISTO_MAXVAL, ctx->numa_node, BHISTO_FLAGS_THREADSAFE);
                if (!private->histo->channels[channel].histograms[hidx]) {
                    dlog_error("Error initializing histograms");
                    return -1;
                }
            }
        }

        char* path = gethistofilename(private);
        private->histo_fd = open(path, O_CREAT | O_WRONLY, 0644);
        dlog_infov("Histogram File Path: %s", path);
        free(path);
        if (private->histo_fd < 0) {
            dlog_error2("open", private->histo_fd);
            return -errno;
        }
        posix_fadvise(private->rawdata_fd, 0, 0, POSIX_FADV_DONTNEED);
    }

    if (!ctx->frame_processor) {
        private->consumer = dqdk_async_processor_init(ctx, 1, private, async_processor);
        if (!private->consumer) {
            dlog_error("Error initializing async consumers");
            return -1;
        }
    }

    return 0;
}

int tristan_fini(dqdk_ctx_t* ctx, dqdk_controller_t* controller, tristan_t* private)
{
    int buffersz = 8192;

    if (ctx && !ctx->frame_processor) {
        dlog_info("Waiting for Async Consumer to finish processing present data and saving files...");
        dqdk_async_processor_cancel(private->consumer);
    }

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

        if (private->histo) {
            for (int channel = 0; channel < CHNLS_COUNT; channel++) {
                for (int hidx = 0; hidx < CHANNELHISTO_COUNT; hidx++) {
                    if (bhisto_csv_dump(private->histo->channels[channel].histograms[hidx], private->histo_fd, channel, hidx) < 0)
                        dlog_errorv("Error writing histogram %d in channel %d", hidx, channel);
                    bhisto_free(private->histo->channels[channel].histograms[hidx]);
                }
            }
            free(private->histo);
        }

        if (fsync(private->histo_fd) || close(private->histo_fd))
            dlog_error("Error while closing histogram file");
    }

    if (dqdk_controller_closed(controller, buffer) < 0)
        dlog_error("Error sending closed status");

    free(buffer);

    return 0;
}

static dqdk_always_inline int histogram_event(tristan_histo_t* histo, tristan_energy_evt_t* evt)
{
    if (evt->channel >= CHNLS_COUNT
        || evt->hist_class >= CHANNELHISTO_COUNT
        || evt->energy >= HISTO_MAXVAL) {
        dlog_errorv("Out of bounds Energy Event: Channel ID=%u, Histogram Index=%u, Energy=%u", evt->channel, evt->hist_class, evt->energy);
        return -1;
    }

    if (bhisto_increment(histo->channels[evt->channel].histograms[evt->hist_class], evt->energy) < 0)
        dlog_errorv("bhisto_increment failed. Channel=%d, Histogram=%d, Bin=%d", evt->channel, evt->hist_class, evt->energy);

    return 0;
}

static dqdk_always_inline int process_events_unrolled16(tristan_t* private, tristan_energy_evt_t* evt, u32 nbEvents)
{
    u32 batch_len = 16;
    u32 mask = batch_len - 1;
    u32 e = 0;
    for (e = 0; e < (nbEvents & ~mask); e += batch_len) {
        histogram_event(private->histo, &evt[e]);
        histogram_event(private->histo, &evt[e + 1]);
        histogram_event(private->histo, &evt[e + 2]);
        histogram_event(private->histo, &evt[e + 3]);
        histogram_event(private->histo, &evt[e + 4]);
        histogram_event(private->histo, &evt[e + 5]);
        histogram_event(private->histo, &evt[e + 6]);
        histogram_event(private->histo, &evt[e + 7]);
        histogram_event(private->histo, &evt[e + 8]);
        histogram_event(private->histo, &evt[e + 9]);
        histogram_event(private->histo, &evt[e + 10]);
        histogram_event(private->histo, &evt[e + 11]);
        histogram_event(private->histo, &evt[e + 12]);
        histogram_event(private->histo, &evt[e + 13]);
        histogram_event(private->histo, &evt[e + 14]);
        histogram_event(private->histo, &evt[e + 15]);
    }
    switch (nbEvents & mask) {
    case 15:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 14:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 13:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 12:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 11:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 10:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 9:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 8:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 7:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 6:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 5:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 4:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 3:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 2:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    case 1:
        histogram_event(private->histo, &evt[e++]); /* fallthrough */
    }

    return 0;
}

#define SWEETSPOT_BATCHSZ 16

static dqdk_always_inline int tristan_process(tristan_t* private, u8* buffer, u32 len, u32 burst)
{
    int ret = 0;
    u32 nbEvents = get_energy_events_count(private->mode, private->payloadsz);
    if (private->histo_fd > 0) {
        // Compute histogram in listwave, listmode, and energy histogram
        for (u32 i = 0; i < burst; i++)
            process_events_unrolled16(private, (tristan_energy_evt_t*)buffer, nbEvents);
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
    int ret = 0, burst = SWEETSPOT_BATCHSZ;
    tristan_t* tristan = (tristan_t*)private;
    u8* buffer = (u8*)calloc(burst, tristan->payloadsz);
    time_t t0 = time(NULL), t1;
    u64 rate = 0;

    if (!buffer)
        return NULL;

    u32 len = tristan->strip_wfm ? TRISTAN_HISTO_EVT_SZ : tristan->payloadsz;
    while (!dqdk_async_processor_has_stopped(proc)) {
        ret = dqdk_async_processor_nfetch(proc, buffer, tristan->payloadsz, burst);
        if (!ret)
            continue;

        ret = tristan_process(tristan, buffer, len, burst);
        if (ret)
            continue;

        rate += burst;
    }

    // Empty ring
    while (!dqdk_async_processor_isempty(proc)) {
        // Fetch from ring
        ret = dqdk_async_processor_nfetch(proc, buffer, tristan->payloadsz, burst);
        if (!ret)
            continue;

        ret = tristan_process(tristan, buffer, len, burst);
        if (ret)
            continue;

        rate += burst;
    }

    t1 = time(NULL);
    printf("Processed %llu in %lusec\n", rate, t1 - t0);

    free(buffer);
    return (void*)(long)ret;
}

static int process_unbuffered_frame(dqdk_worker_t* worker, u8* data, u32 datalen)
{
    tristan_t* tristan = (tristan_t*)worker->private;
    return tristan_process(tristan, data, datalen, 1);
}

void tristan_usage(char* program)
{
    printf("Usage: %s -i <interface_name> -q <hardware_queue_id>\n", program);
    printf("Arguments:\n");
    printf("    -a <ports-range>             Accept source ports range e.g. 5000-5002 will reject all ports except 3 ports 5000, 5001 & 5002\n");
    printf("    -d <duration>                DAQ duration\n");
    printf("    -i <interface>               Set NIC to work on\n");
    printf("    -q <qid[-qid]>               Set range of hardware queues to work on e.g. -q 1 or -q 1-3.\n");
    printf("                                 Specifying multiple queues will launch a thread for each queue except if -p poll\n");
    printf("    -v                           Verbose\n");
    printf("    -b <size>                    Set batch size. Default: 64\n");
    printf("    -w                           Use XDP need wakeup flag\n");
    printf("    -s                           Expected Payload Size. Default: 3392\n");
    printf("    -l                           Dump latency values as a CSV file. Requires -D\n");
    printf("    -m <mode>                    Set TRISTAN Mode: waveform|listwave|listmode|energy-histo\n");
    printf("    -A <irq1,irq2,...>           Set affinity mapping between application threads and drivers queues\n");
    printf("                                 e.g. q1 to irq1, q2 to irq2,...\n");
    printf("    -B                           Enable NAPI busy-poll\n");
    printf("    -I                           This DQDK instance ID\n");
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
    int opt_dqdk_id = -1;
    u32 opt_batchsize = 64, opt_queues[MAX_QUEUES], opt_irqs[MAX_QUEUES];
    u8 opt_umem_flags = 0, opt_stripwfm = 0;
    u32 opt_payloadsz = 3392;
    s64 opt_duration = 0;
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

    while ((opt = getopt(argc, argv, "a:b:d:hi:q:ws:lm:A:BDI:HGSP:W")) != -1) {
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
        case 'd':
            opt_duration = atoll(optarg);
            break;
        case 'i':
            opt_ifname = optarg;
            break;
        case 'I':
            opt_dqdk_id = atoi(optarg);
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
            else if (strcmp(optarg, tristan_modes[TRISTAN_MODE_LISTMODE]) == 0)
                private.mode = TRISTAN_MODE_LISTMODE;
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

    if (opt_dqdk_id < 0) {
        dlog_error("Invalid DQDK ID. Use positive integer");
        goto cleanup;
    }

    dlog_info("Waiting for Control Software to connect...");
    controller = dqdk_controller_start(CONTROLLER_PORT + opt_dqdk_id);
    if (controller == NULL)
        goto cleanup;

    if (opt_duration <= 0) {
        dlog_error("Invalid DAQ duration: it cannot be zero or negative");
        goto cleanup;
    }

    dqdk_controller_report_status(controller, DQDK_STATUS_STARTED, NULL);

    dqdk_frame_processor_t proc = is_store_raw(RINGBUFSZ, opt_payloadsz, opt_ifname, private.mode, opt_duration) ? NULL : process_unbuffered_frame;
    ctx = dqdk_ctx_init(opt_ifname, opt_queues, nbqueues, opt_umem_flags, UMEM_SIZE, opt_batchsize, opt_payloadsz, RINGBUFSZ, proc, &opts);

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

    if (tristan_init(ctx, &private, basedir, opt_duration, opt_dqdk_id, opt_stripwfm) < 0) {
        dqdk_controller_error(controller);
        goto cleanup;
    }

    for (u32 i = 0; i < nbqueues; i++) {
        if (dqdk_worker_init(ctx, opt_queues[i], opt_irqs[i], (void*)&private) < 0) {
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
