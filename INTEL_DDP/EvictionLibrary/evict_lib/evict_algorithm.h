#ifndef EVICT_ALGORITHM 
#define EVICT_ALGORITHM

#include "evict_set.h"

enum Cache_Level { L1, L2, L3, SYSTEM, MEMORY }; 


/*
    Implementing Algorithm 2 from "Theory and Practice of Finding Eviction Sets" Vila et al. IEEE SP 2019

    Didn't like the way it was written in the code provided with the paper so I'm going to do it myself. 
*/

/* Determine level given latency */
enum Cache_Level determine_cache_level(uint64_t access_latency);


/* Convert cache_level enum to a printable string */
char* cache_level_to_string(enum Cache_Level cache_level);


/*
    Generates a minimal eviction set given 2 inputs. 
    Inputs: Cache level, and the initial large eviction set (with size as well)

    Note: if a L1 eviction set is requested it skips the algorithm and directly generates an eviction
    set for the target L1 since the page offset directly covers the set index. You also don't need to 
    feed the initial buffer, those fields can be NULL
*/
Evict_Set* generate_eviction_set(uint64_t addr, enum Cache_Level cache_level, uint64_t *init_buffer, uint64_t init_buffer_size); 


#endif
