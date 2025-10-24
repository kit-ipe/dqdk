#ifndef DQDK_ASYNC_PROCESSOR
#define DQDK_ASYNC_PROCESSOR

#include <stdlib.h>
#include <stdatomic.h>

#include "ctypes.h"

typedef void* (*dqdk_async_func_t)(void* private);

typedef struct {
    u8 nb_threads;
    void* private;
    dqdk_async_func_t func;
    pthread_t* threads;
    atomic_bool stop_flag;
} dqdk_async_processor_t;

dqdk_async_processor_t* dqdk_async_processor_init(u8 nb_threads, void* private, dqdk_async_func_t func);
int dqdk_async_processor_cancel(dqdk_async_processor_t* processor);
int dqdk_async_processor_has_stopped(dqdk_async_processor_t* processor);

#endif
