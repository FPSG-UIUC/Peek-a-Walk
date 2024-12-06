#ifndef EVICT_SET 
#define EVICT_SET

#include "util.h"

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>

/* Note: This won't work on on a different architecture. These threshold values are measured */
// TODO auto detect the thresholds? 

// These numbers are for the Intel 13th generation Raptor Lake Architecture and for rdtscp timing
#define L1_THRESHOLD 6
#define L2_THRESHOLD 16
#define L3_THRESHOLD 60 
#define SYSTEMCACHE_THRESHOLD 100

// Ways 
#define L1_WAYS 12
#define L2_WAYS 16 

// Helper macros 
#define CACHE_OFFSET_ADDR_MASK 0x3f
#define L1_SET_ADDR_MASK 0xfc0 

// Defines an eviction set 
typedef struct Evict_Set_S {
    uint64_t **ptrs; 
    uint64_t size;
    uint64_t *buffer;
    uint64_t **ll_head; // linked list
} Evict_Set;

/* Create/Destroy Eviction Set */
Evict_Set* init_evict_set(uint64_t size);

/* Fill the eviction set with a given stride for a given addr */
/* TODO need to deal with the dead buffer memory at the end of it */
__attribute__((noinline))
void fill_evict_set(uint64_t addr, uint64_t stride, Evict_Set *to_fill);

/* Destroy the eviction set */
void destroy_evict_set(Evict_Set *to_destroy);

/* Prime Eviction Set */
/* Note: Noticed some weird cache behavior when instead of a fixed iteration loop it looped until the 
   probe step returned zero misses. Initially I used the same indexes array as the probe step in the test 
   function and instead of observing a single miss it seemed like the entire eviction set was evicted 
   from as the following probe step recorded 12 misses. After changing it so this indexes did not 
   use the same indexes array as the probe step we no longer saw the 12 misses being recorded. This is
   very strange behavior and my hypothesis is that there is some thing that kicks the L1 cache set (all 12 ways)
   to the L2 cache. But not well studied still pretty confused why that happened. */
__attribute__((noinline))
void prime_evict_set(Evict_Set *to_prime);

/* Probe Eviction Set */
/* Returns the # of misses in the eviction set */
// TODO very specific to L1 cache --> need to make this more general 
// TODO switch to pointer chasing 
__attribute__((noinline))
int probe_evict_set(Evict_Set *to_probe, int* indexes);

#endif