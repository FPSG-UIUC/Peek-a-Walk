#pragma once 
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include "macros.h"


struct orderOracle {
	char *data;                 				// eviction set
	size_t size;                				// eviction set size
    uint64_t pwc_evict_sizes[MAX_PAGE_LEVELS]; 	// pwc evict sizes 
};

struct orderOracle* new_orderOracle(uint64_t *pwc_evict_sizes, const uint64_t *pagetable_region_sizes);
void free_orderOracle(struct orderOracle *order_oracle);