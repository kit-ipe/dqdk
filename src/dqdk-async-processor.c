#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include "dqdk-async-processor.h"

static void dqdk_async_proc_free(dqdk_async_processor_t* proc)
{
    if (!proc)
        return;

    if (proc->threads)
        free(proc->threads);
    free(proc);
}

dqdk_async_processor_t* dqdk_async_processor_init(u8 nb_threads, void* private, dqdk_async_func_t func)
{
    dqdk_async_processor_t* proc = (dqdk_async_processor_t*)malloc(sizeof(dqdk_async_processor_t));
    if (!proc)
        goto err;

    if (nb_threads != 1)
        goto err;

    proc->func = func;
    proc->private = private;
    proc->nb_threads = nb_threads;
    proc->threads = (pthread_t*)calloc(nb_threads, sizeof(pthread_t));
    atomic_init(&proc->stop_flag, 0);
    if (!proc->threads)
        goto err;

    for (size_t i = 0; i < proc->nb_threads; i++)
        if (pthread_create(&proc->threads[i], NULL, proc->func, proc))
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
        return 1;
    return atomic_load_explicit(&processor->stop_flag, memory_order_relaxed);
}
