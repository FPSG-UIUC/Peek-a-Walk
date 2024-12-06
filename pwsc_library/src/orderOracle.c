#include "orderOracle.h"

// Creates a PWC order oracle
// This can be hacked to become a memory mapped order oracle but just setting large eviction sizes so 
// that the order oracle becomes a giant flush primitive. Then the programmer just needs to rely on 
// selectively allocate memory to order the page walk accesses
struct orderOracle* new_orderOracle(uint64_t *pwc_evict_sizes, const uint64_t *pagetable_region_sizes) {
	struct orderOracle *order_oracle;

	if (!(order_oracle = malloc(sizeof *order_oracle)))
		return NULL;

    for(uint64_t level = 0; level < MAX_PAGE_LEVELS; ++level) {
        order_oracle->pwc_evict_sizes[level] = pwc_evict_sizes[level]; 
	}

	for (uint64_t level = 0; level < MAX_PAGE_LEVELS; ++level) { 
		uint64_t cur_level_pwc_entries = pwc_evict_sizes[level]; 
		uint64_t stride = pagetable_region_sizes[level];
		order_oracle->size = max(order_oracle->size, cur_level_pwc_entries * stride);
	}

	if (!(order_oracle->data = mmap(NULL, order_oracle->size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0))) {
		fprintf(stderr, "Error allocating order oracle memory!\n");
		goto err_free_cache;
	}

	return order_oracle;

err_free_cache:
	free(order_oracle);
	return NULL;
}

void free_orderOracle(struct orderOracle *order_oracle) {
	munmap(order_oracle->data, order_oracle->size);
	free(order_oracle);
}
