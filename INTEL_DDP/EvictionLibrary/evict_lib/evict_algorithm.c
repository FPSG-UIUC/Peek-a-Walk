#include "evict_algorithm.h"


enum Cache_Level determine_cache_level(uint64_t access_latency) {
    if(access_latency <= L1_THRESHOLD) return L1; 
    else if(access_latency < L2_THRESHOLD) return L2; 
    else if(access_latency < L3_THRESHOLD) return L3; 
    else if(access_latency < SYSTEMCACHE_THRESHOLD) return SYSTEM;
    else return MEMORY;
}

char* cache_level_to_string(enum Cache_Level cache_level) {
    if(cache_level == L1) return "L1"; 
    else if(cache_level == L2) return "L2"; 
    else if(cache_level == L3) return "L3"; 
    else if(cache_level == SYSTEM) return "SYSTEM";
    else return "MEMORY";
}

Evict_Set* generate_eviction_set(uint64_t addr, enum Cache_Level cache_level, uint64_t *init_buffer, uint64_t init_buffer_size) {
    // if the cache level is L1 we can actually just straight up generate an eviction set
    if(cache_level == L1) {
        Evict_Set *l1_evict_set = init_evict_set(L1_WAYS); 
        fill_evict_set(addr, 4096, l1_evict_set);
        return l1_evict_set; 
    }

    // TODO other cache eviction sets

    return NULL; 
}