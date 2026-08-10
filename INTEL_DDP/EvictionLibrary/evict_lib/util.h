#ifndef EVICT_UTIL 
#define EVICT_UTIL

#include <unistd.h> 
#include <stdint.h>
#include <x86intrin.h>
#include <assert.h> 

#define MSB_MASK 0x8000000000000000

/* Timing latency to a specific memory address using rdtsc */
uint64_t time_access(uint64_t *addr, uint64_t __trash); 

/* Using cflush kick a specific addr out of caches */
uint64_t clflush(uint64_t *addr, uint64_t __trash); 

/* Shuffle function - Source listed in util.c */
void shuffle(int *array, size_t n); 

/* Generate Random Indexes */
int* generate_indexes(uint64_t size); 

/* Multiplication sleep */
uint64_t c_sleep(uint64_t duration, uint64_t __trash);

#endif 