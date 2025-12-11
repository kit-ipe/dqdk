#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include "dqdk-async-processor.h"
#include "ds/cne_ring.h"
#include "dqdk.h"

struct dqdk_async_processor {
    u8 nb_threads;
    void* private;
    dqdk_async_func_t func;
    dqdk_async_func_t init_func;
    dqdk_async_func_t fini_func;
    pthread_t* threads;
    atomic_bool stop_flag;
    dqdk_ctx_t* ctx;
};

static void dqdk_async_proc_free(dqdk_async_processor_t* proc)
{
    if (!proc)
        return;

    if (proc->threads)
        free(proc->threads);
    free(proc);
}

static void* _runner(void* arg)
{
    dqdk_async_processor_t* proc = (dqdk_async_processor_t*)arg;
    return proc->func(proc, proc->private);
}

dqdk_async_processor_t* dqdk_async_processor_init(dqdk_ctx_t* ctx, u8 nb_threads, void* private, dqdk_async_func_t func)
{
    dqdk_async_processor_t* proc = (dqdk_async_processor_t*)malloc(sizeof(dqdk_async_processor_t));
    if (!proc)
        goto err;

    if (nb_threads != 1)
        goto err;

    proc->ctx = ctx;
    proc->func = func;
    proc->private = private;
    proc->nb_threads = nb_threads;
    proc->threads = (pthread_t*)calloc(nb_threads, sizeof(pthread_t));
    atomic_init(&proc->stop_flag, 0);
    if (!proc->threads)
        goto err;

    for (size_t i = 0; i < proc->nb_threads; i++)
        if (pthread_create(&proc->threads[i], NULL, _runner, proc))
            goto err;
    return proc;

err:
    dqdk_async_proc_free(proc);
    return NULL;
}

int dqdk_async_processor_cancel(dqdk_async_processor_t* processor)
{
    if (!processor)
        return -EINVAL;

    atomic_store_explicit(&processor->stop_flag, 1, memory_order_relaxed);
    for (size_t i = 0; i < processor->nb_threads; i++)
        pthread_join(processor->threads[i], NULL);

    dqdk_async_proc_free(processor);
    return 0;
}

int dqdk_async_processor_has_stopped(dqdk_async_processor_t* processor)
{
    if (!processor)
        return -EINVAL;
    return atomic_load_explicit(&processor->stop_flag, memory_order_relaxed);
}

int dqdk_async_processor_fetch(dqdk_async_processor_t* processor, u8* buffer, u32 len)
{
    if (!processor)
        return -EINVAL;

    return cne_ring_dequeue_elem(processor->ctx->ring, buffer, len);
}

int dqdk_async_processor_isempty(dqdk_async_processor_t* processor)
{
    if (!processor)
        return -EINVAL;

    return cne_ring_empty(processor->ctx->ring);
}

int dqdk_async_processor_numworkers(dqdk_async_processor_t* proc)
{
    if (!proc)
        return -EINVAL;

    return proc->nb_threads;
}
