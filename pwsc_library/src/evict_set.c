#include "evict_set.h"
#include "util.h"

/* Create/Destroy Eviction Set */
Evict_Set* init_evict_set(uint64_t size) {
    Evict_Set *ret = malloc(sizeof(Evict_Set)); 
    ret->size = size; 
    ret->ptrs = malloc(sizeof(uint64_t *) * size);
    return ret; 
}

/* Fill the eviction set with a given stride for a given addr */
__attribute__((noinline))
void fill_evict_set(uint64_t addr, uint64_t stride, Evict_Set *to_fill) {
    uint64_t num_ptrs = to_fill->size; 
    char *buffer = malloc(stride * num_ptrs + 2 * 4096); // give a page of space for alignment 
    to_fill->buffer = (uint64_t *)buffer;
    buffer = ((buffer - ((uint64_t)buffer % 4096)) + 4096) + (addr & L1_SET_ADDR_MASK); 
    for(uint64_t i = 0; i < num_ptrs; i++)
        to_fill->ptrs[i] = (uint64_t *)(buffer + (stride * i)); 

    // set up linked list ll 
    uint64_t *head = to_fill->ptrs[0]; 
    uint64_t *cur = head; 
    for(uint64_t i = 1; i < num_ptrs; i++) {
        *cur = (uint64_t) to_fill->ptrs[i]; 
        cur = (uint64_t *)*cur; 
    }
    *cur = (uint64_t)head; 
    to_fill->ll_head = (uint64_t **)head; 
}

/* Destroy the eviction set */
void destroy_evict_set(Evict_Set *to_destroy) {
    free(to_destroy->ptrs);
    if(to_destroy->buffer) free(to_destroy->buffer);
    free(to_destroy);
}

/* Prime Eviction Set */
/* Note: Noticed some weird cache behavior when instead of a fixed iteration loop it looped until the 
   probe step returned zero misses. Initially I used the same indexes array as the probe step in the test 
   function and instead of observing a single miss it seemed like the entire eviction set was evicted 
   from as the following probe step recorded 12 misses. After changing it so this indexes did not 
   use the same indexes array as the probe step we no longer saw the 12 misses being recorded. This is
   very strange behavior and my hypothesis is that there is some thing that kicks the L1 cache set (all 12 ways)
   to the L2 cache. But not well studied still pretty confused why that happened. */
__attribute__((noinline))
void prime_evict_set(Evict_Set *to_prime) {
    // LL low noise prime 
    uint64_t **head = to_prime->ll_head; 
    uint64_t **cur = head; 
    for(int i = 0; i < 5; i++) {
        asm volatile( // SUPER OPTIMIZED PRIME+PROBE FOR RAPTOR LAKE --> exactly L1_WAYS (12) 
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            : "=r" (cur)
            : "0" (cur)
            : );
    }
}

/* Probe Eviction Set */
/* Returns the # of misses in the eviction set */
__attribute__((noinline))
int probe_evict_set(Evict_Set *to_probe, int* indexes) {
    uint64_t __trash = 0; 
    int num_misses = 0; 
    for(uint64_t i = 0; i < to_probe->size; i++) {
        int idx = indexes[i]; 
        uint64_t time = time_access(to_probe->ptrs[idx], __trash);
        __trash = (__trash | time) & (MSB_MASK - 1);  // dependency 
        if(time > L1_THRESHOLD) num_misses++; 
    }
    return num_misses | (__trash & MSB_MASK);
}