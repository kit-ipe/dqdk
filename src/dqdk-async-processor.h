#ifndef DQDK_ASYNC_PROCESSOR
#define DQDK_ASYNC_PROCESSOR

#include <stdlib.h>
#include <stdatomic.h>

#include "ctypes.h"
#include "dqdk.h"

typedef struct dqdk_async_processor dqdk_async_processor_t;

typedef void* (*dqdk_async_func_t)(dqdk_async_processor_t* proc, void* private);

dqdk_async_processor_t* dqdk_async_processor_init(dqdk_ctx_t* ctx, u8 nb_threads, void* private, dqdk_async_func_t processsor);
int dqdk_async_processor_cancel(dqdk_async_processor_t* processor);
int dqdk_async_processor_has_stopped(dqdk_async_processor_t* processor);
int dqdk_async_processor_fetch(dqdk_async_processor_t* processor, u8* buffer, u32 len);
int dqdk_async_processor_isempty(dqdk_async_processor_t* processor);
int dqdk_async_processor_numworkers(dqdk_async_processor_t* proc);
#endif
