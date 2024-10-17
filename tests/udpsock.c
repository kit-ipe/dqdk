#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <sys/signal.h>
#include <stdbool.h>

#include "../src/ctypes.h"

#define TRISTAN_FE_PORT 5000
#define log2l(x) (31 - __builtin_clz(x))

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

typedef struct {
    u32 histograms[HISTO_COUNT][HISTO_BINS];
} chnl_t;

typedef struct {
    chnl_t channels[CHNLS_COUNT];
} tristan_histo_t;

volatile bool _exitflag = false;

#define SERVER_PORT 5001 // Server port
#define SERVER_IP "192.168.1.20" // Server IP address

#define SOURCE_PORT 5001
#define SOURCE_IP "192.168.1.100"

#define BUFFER_SIZE 3392 // Buffer size for messages

#define TRISTAN_HISTO_EVT_SZ sizeof(energy_evt_t)

#define HISTO_BINS (2 << 15) // 2^16 bins
#define HISTO_COUNT 8 // usually 5 or 6
#define CHNLS_1TILE 166
#define TILES_COUNT 9
#define CHNLS_COUNT (CHNLS_1TILE * TILES_COUNT)

// Structure to pass arguments to threads
typedef struct {
    int thread_id;
    struct sockaddr_in server_addr;
    struct sockaddr_in source_addr;
} thread_arg_t;

tristan_histo_t* histo = NULL;
u64 pkt_count = 0;

void histogram(unsigned char* data, int datalen)
{
    energy_evt_t* evts = (energy_evt_t*)data;
    int nbevts = datalen / TRISTAN_HISTO_EVT_SZ;

    for (int i = 0; i < nbevts; i++) {
        energy_evt_t evt = evts[i];
        // if (xsk->debug) {
        //     dlog_infov("Evnt %d: Energy=%u; TimeStamp=%llu; Channel=%d; Mask=%d, Difference from previous EvtID: %d\n", evt.id,
        //         evt.energy, (u64)evt.timestamp, evt.channel, evt.mask, last_evt_id != -1 ? evt.id - last_evt_id - 1 : 0);
        // }
        int histo_idx = log2l(evt.mask);
        u32* counter = &histo->channels[evt.channel].histograms[histo_idx][evt.energy];
        atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);

        // if (last_evt_id != -1 && evt.id - last_evt_id > 1)
        //     xsk->stats.tristan_histogram_lost_evts += evt.id - last_evt_id - 1;

        // last_evt_id = evt.id;
    }
}

// Thread function to receive multiple messages
void* receive_messages(void* arg)
{
    thread_arg_t* thread_arg = (thread_arg_t*)arg;
    int thread_id = thread_arg->thread_id;
    struct sockaddr_in server_addr = thread_arg->server_addr;

    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket creation failed");
        pthread_exit(NULL);
    }

    // Set the SO_REUSEPORT option
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEPORT) failed");
        close(sock);
        pthread_exit(NULL);
    }

    // Bind the socket to the address and port
    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(sock);
        pthread_exit(NULL);
    }

    u8 buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(server_addr);

    // Receive multiple messages
    while (!_exitflag) {

        int len = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&server_addr, &addr_len);
        if (len <= 0) {
            perror("recvfrom failed");
            continue;
        }
        
        atomic_fetch_add_explicit(&pkt_count, 1, memory_order_relaxed);
        histogram(buffer, len);
    }

    close(sock);
    printf("Thread %d finished receiving messages.\n", thread_id);

    return NULL;
}

void handler(int signo)
{
    switch (signo) {
    case SIGINT:
    case SIGTERM:
        _exitflag = true;
        break;
    default:
        break;
    }
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <num_threads>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int num_threads = atoi(argv[1]);
    if (num_threads <= 0) {
        fprintf(stderr, "Invalid number of threads: %d\n", num_threads);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, handler);
    signal(SIGTERM, handler);

    pthread_t* threads = calloc(num_threads, sizeof(pthread_t));
    thread_arg_t* thread_args = calloc(num_threads, sizeof(thread_arg_t));
    struct sockaddr_in server_addr;
    struct sockaddr_in source_addr;


    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    memset(&source_addr, 0, sizeof(server_addr));
    source_addr.sin_family = AF_INET;
    source_addr.sin_port = htons(SOURCE_PORT);
    source_addr.sin_addr.s_addr = inet_addr(SOURCE_IP);

    // Create and start threads to receive messages concurrently
    for (int i = 0; i < num_threads; i++) {
        thread_args[i].thread_id = i;
        thread_args[i].server_addr = server_addr;
        thread_args[i].source_addr = source_addr;

        if (pthread_create(&threads[i], NULL, receive_messages, (void*)&thread_args[i]) != 0) {
            perror("pthread_create failed");
            exit(EXIT_FAILURE);
        }
    }

    // Wait for all threads to finish
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(thread_args);

    printf("Pkt count: %llu\n", pkt_count);
    return 0;
}
