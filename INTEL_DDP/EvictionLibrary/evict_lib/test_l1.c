#include "evict_algorithm.h"
#include "evict_set.h"

int main(void) {

    // allocate test addr 
    uint64_t *addr_testing = calloc(1, 64); 
    
    // Get eviction set 
    Evict_Set *l1_evict_set = init_evict_set(12); // L1 evict set 
    fill_evict_set((uint64_t)addr_testing, 4096, l1_evict_set); // generate eviction set 

    // test 
    uint64_t __trash = rand() & (MSB_MASK - 1);  
    uint64_t time = 0; 

    // generate indexes for accessing (shuffles, avoid prefetchers)
    int misses = 0; 
    int* indexes = generate_indexes(12);

    // warmup 
    asm("nop\nnop\nnop\nnop\n" ::: "cc");
    for(int i = 0; i < 10; i++) { 
        *addr_testing = (rand() | __trash) & (MSB_MASK - 1); 
        prime_evict_set(l1_evict_set);
        probe_evict_set(l1_evict_set, indexes);
    }
    asm("nop\nnop\nnop\nnop\n" ::: "cc");

    // get data
    uint64_t repititions = 2048;
    uint64_t base[repititions], atck[repititions];
    for(int k = 0; k < repititions; k++) {
        _mm_mfence();
        prime_evict_set(l1_evict_set); 
        misses = probe_evict_set(l1_evict_set, indexes);
        // printf("Didn't touch target address, probe num_misses %d\n", misses);
        base[k] = misses; 

        _mm_mfence(); 
        prime_evict_set(l1_evict_set);
        *addr_testing = (rand() | __trash) & (MSB_MASK - 1); 
        misses = probe_evict_set(l1_evict_set, indexes);
        // printf("Touched target addr, probe num_misses %d\n", misses);
        atck[k] = misses; 
    }

    // output 
    printf("Base: ");
    for(int i = 0; i < repititions; i++) printf("%lu ", base[i]);
    printf("\n");
    printf("Atck: ");
    for(int i = 0; i < repititions; i++) printf("%lu ", atck[i]);
    printf("\n");

    // calculate averages 
    uint64_t avg_base = 0, avg_atck = 0; 
    for(int i = 0; i < repititions; i++) {
        avg_base += base[i];
        avg_atck += atck[i];
    }
    avg_base /= repititions; 
    avg_atck /= repititions; 
    printf("Target address %p set: %lu\toffset: %lu\n", addr_testing, (uint64_t)addr_testing & L1_SET_ADDR_MASK,  (uint64_t)addr_testing & CACHE_OFFSET_ADDR_MASK);
    printf("Avg Base: \t%lu\n", avg_base);
    printf("Avg Atck: \t%lu\n", avg_atck);

    return 1; 
}