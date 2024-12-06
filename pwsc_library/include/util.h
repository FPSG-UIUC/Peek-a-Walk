#ifndef EVICT_UTIL 
#define EVICT_UTIL

#include <unistd.h> 
#include <stdint.h>
#include <x86intrin.h>
#include <assert.h> 
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sched.h>
#include "macros.h"
#include "mapping.h"

#define KB(x) (x * 1024) 
#define MSB_MASK 0x8000000000000000

/* Timing latency to a specific memory address using rdtsc */
uint64_t time_access(uint64_t *addr, uint64_t __trash); 

/* Using cflush kick a specific addr out of caches */
uint64_t clflush(uint64_t *addr, uint64_t __trash); 

/* Shuffle function - Source listed in util.c */
void evict_shuffle(int *array, size_t n); 

/* Generate Random Indexes */
int* generate_indexes(uint64_t size); 

/* Multiplication sleep */
uint64_t c_sleep(uint64_t duration, uint64_t __trash);

/* Pin CPU */
void pin_cpu(size_t core_ID);

/* Check bit accuracy */
uint64_t bit_accuracy_checker(uint64_t guess, uint64_t correct);

#endif 