#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdatomic.h>

#include "ds/bhisto.h"

bhisto_t* bhisto(u32 bucketsnb, u32 max)
{
    u32 bucketsz = max / bucketsnb;
    int finalbucketsz = max % bucketsnb;

    if (bucketsnb == 0 || bucketsnb == 1 || max == 0)
        return NULL;

    if (finalbucketsz != 0)
        bucketsnb++;

    bucket_t* buckets = (bucket_t*)calloc(bucketsnb, sizeof(bucket_t));
    if (!buckets)
        return NULL;

    bhisto_t* bhist = (bhisto_t*)calloc(1, sizeof(bhisto_t));
    if (!bhist) {
        free(buckets);
        return NULL;
    }

    bhist->bucket_count = bucketsnb;
    bhist->bucketsz = bucketsz;
    bhist->buckets = buckets;
    bhist->max_value = max;

    if (finalbucketsz)
        bhist->final_bucketsz = finalbucketsz;

    return bhist;
}

u32* bhisto_get(bhisto_t* bhisto, u32 bin)
{
    if (!bhisto)
        return NULL;

    if (bin > bhisto->max_value)
        return NULL;

    int index = bin - 1;
    int bid = 0, mod = 0;
    if (bin) {
        bid = index / bhisto->bucketsz;
        mod = index % bhisto->bucketsz;
    }

    u32* expected = atomic_load_explicit(&bhisto->buckets[bid].bucket_array, memory_order_relaxed);
    u32* allocated = NULL;
    while (expected == NULL) {
        if (!allocated) {
            allocated = (u32*)calloc(bhisto->bucketsz, sizeof(u32));
            if (!allocated)
                return NULL;
        }

        if (atomic_compare_exchange_weak_explicit(&bhisto->buckets[bid].bucket_array,
                &expected, allocated, memory_order_release, memory_order_relaxed))
            break;

        if (expected != NULL)
            free(allocated);
    }

    return &bhisto->buckets[bid].bucket_array[mod];
}

int bhisto_increment(bhisto_t* bhisto, u32 bin)
{
    u32* freq = bhisto_get(bhisto, bin);
    if (!freq)
        return -EFAULT;

    int old = atomic_fetch_add_explicit(freq, 1, memory_order_relaxed);
    return old + 1;
}

int bhisto_free(bhisto_t* bhisto)
{
    if (!bhisto)
        return -EINVAL;

    for (size_t i = 0; i < bhisto->bucket_count; i++)
        if (bhisto->buckets[i].bucket_array)
            free(bhisto->buckets[i].bucket_array);
    free(bhisto->buckets);

    free(bhisto);
    return 0;
}

int bhisto_iterate(bhisto_t* bhisto, bhisto_iterator_t iterator, void* priv)
{
    if (!bhisto || !iterator)
        return -EINVAL;

    u32 count = bhisto->final_bucketsz == 0 ? bhisto->bucket_count : bhisto->bucket_count - 1;
    for (u32 bid = 0; bid < count; bid++) {
        if (bhisto->buckets[bid].bucket_array) {
            for (u32 idx = 0; idx < bhisto->bucketsz; idx++) {
                if (iterator(bid * bhisto->bucketsz + idx + 1, bhisto->buckets[bid].bucket_array[idx], priv) < 0)
                    return -EFAULT;
            }
        }
    }

    int lastbucket = bhisto->bucket_count - 1;
    if (bhisto->buckets[lastbucket].bucket_array) {
        for (size_t j = 0; j < bhisto->final_bucketsz; j++)
            if (iterator(lastbucket * bhisto->bucketsz + j + 1, bhisto->buckets[lastbucket].bucket_array[j], priv) < 0)
                return -EFAULT;
    }

    return 0;
}

int bhisto_buckets(bhisto_t* bhist)
{
    if (!bhist)
        return -EINVAL;

    return bhist->bucket_count;
}

int bhisto_bucketlen(bhisto_t* bhist)
{
    if (!bhist)
        return -EINVAL;

    return bhist->bucketsz;
}
