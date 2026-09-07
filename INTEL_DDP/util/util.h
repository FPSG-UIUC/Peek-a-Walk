#ifndef _ALAN_UTIL
#define _ALAN_UTIL

#define _GNU_SOURCE
#include <unistd.h> 
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <x86intrin.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sched.h>

#define MSB_MASK 0x8000000000000000
#define DATA_BUFFER_MASK (1<<20)
#define MB(x) (x * 1024 * 1024)
#define KB(x) (x * 1024) 
#define U64S_PER_CACHE_LINE 8

// setup macros
#define SETUP_AOP(name) \
    uint64_t name##_size = training_size + test_ptr_after + 1; \
    uint64_t *name = malloc(sizeof(uint64_t) * name##_size + MB(2)); \
    for(int i = 0; i < name##_size; i++) \
        name[i] = rand() & (MSB_MASK - 1); \
    name = (uint64_t *)((MB(2) - ((uint64_t)name % MB(2))) + (char *)name); \
    assert((uint64_t)name % MB(2) == 0)

#define SETUP_DATA_BUFFER(name) \
    uint64_t name##_size = DATA_BUFFER_MASK * U64S_PER_CACHE_LINE; \
    uint64_t *name = malloc((sizeof(uint64_t) * name##_size) + MB(2)); \
    for(int i = 0; i < name##_size; i++) \
        name[i] = rand() & (MSB_MASK - 1); \
    name = (uint64_t *)((MB(2) - ((uint64_t)name % MB(2))) + (char *)name); \
    assert((uint64_t)name % MB(2) == 0)

#define max(a,b) \
({ __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b; })

void pin_cpu(size_t core_ID);

uint64_t time_access(uint64_t *addr, uint64_t __trash);

uint64_t clflush(uint64_t *addr, uint64_t __trash);

int compare( const void* a, const void* b);

uint64_t c_sleep(uint64_t duration, uint64_t __trash);

/* Shuffle function - Source listed in util.c */
void shuffle(int *array, size_t n); 

/* Generate Random Indexes */
int* generate_indexes(uint64_t size); 

/* DOITM functions */
uint64_t read_doitm(uint64_t core_id); 
void set_doitm(uint64_t core_id); 
void unset_doitm(uint64_t core_id); 

/* Training Loop */
uint64_t shared_load_gadget(uint64_t *ptr, uint64_t deref_flag, uint64_t __trash);

#endif