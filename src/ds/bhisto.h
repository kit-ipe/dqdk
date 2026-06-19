#ifndef DQDK_BHISTO
#define DQDK_BHISTO

#include "ctypes.h"
typedef struct {
    _Atomic(u32*) bucket_array;
} bucket_t;

#define BHISTO_FLAGS_THREADSAFE (1)
#define BHISTO_FLAGS (BHISTO_FLAGS_THREADSAFE)

typedef struct {
    u32 bucket_count;
    u32 bucketsz;
    u32 final_bucketsz;
    u32 max_value;
    u32 order;
    bucket_t* buckets;
    int numa_node;
    int flags;
} bhisto_t;

typedef int (*bhisto_iterator_t)(u32 bin, u32 freq, void* priv);

bhisto_t* bhisto(u32 buckets, u32 maxvalue, int numa_node, int flags);
dqdk_always_inline u32* bhisto_get(bhisto_t* bhisto, u32 index);
dqdk_always_inline int bhisto_increment(bhisto_t* bhisto, u32 index);
int bhisto_free(bhisto_t* bhisto);
int bhisto_buckets(bhisto_t* bhist);
int bhisto_bucketlen(bhisto_t* bhist);
int bhisto_iterate(bhisto_t* bhist, bhisto_iterator_t iterator, void* priv);

#endif
