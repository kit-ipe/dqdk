#ifndef DQDK_BHISTO
#define DQDK_BHISTO

#include "ctypes.h"
typedef struct {
    _Atomic(u32*) bucket_array;
} bucket_t;

typedef struct {
    u32 bucket_count;
    u32 bucketsz;
    u32 final_bucketsz;
    u32 max_value;
    bucket_t* buckets;
} bhisto_t;

typedef int (*bhisto_iterator_t)(u32 bin, u32 freq, void* priv);

bhisto_t* bhisto(u32 buckets, u32 maxvalue);
u32* bhisto_get(bhisto_t* bhisto, u32 index);
int bhisto_increment(bhisto_t* bhisto, u32 index);
int bhisto_free(bhisto_t* bhisto);
int bhisto_buckets(bhisto_t* bhist);
int bhisto_bucketlen(bhisto_t* bhist);
int bhisto_iterate(bhisto_t* bhist, bhisto_iterator_t iterator, void* priv);

#endif
