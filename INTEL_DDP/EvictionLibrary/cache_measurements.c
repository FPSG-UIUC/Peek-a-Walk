/*
    Measure latency of cache. L1 L2 and LLC
*/
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
#include <sys/mman.h>

#define MSB_MASK 0x8000000000000000

uint64_t time_access(uint64_t *addr, uint64_t __trash) { // TODO check overhead 
    uint64_t T0, T1, time;

    // enforce ordering 
    _mm_mfence();
    _mm_lfence();

    // measuring timing
    T0 = __rdtscp( &__trash ); 

    // serialize the rdtscp 
    _mm_lfence();

    __trash = *addr; 

    // serialize the rdtscp
    _mm_lfence();

    // measuring timing 
    T1 = __rdtscp( &__trash ); 

    // serialize 
    _mm_lfence();
    time = T1 - T0; 

    // noise measurements 
    _mm_mfence();
    _mm_lfence();
    T0 = __rdtscp( &__trash ); 
    _mm_lfence();
    _mm_lfence();
    T1 = __rdtscp( &__trash ); 
    _mm_lfence();

    // subtract out noise
    return (time - (T1 - T0)) | (__trash & MSB_MASK); // TODO this sneaks an extra AND call into the timing measurement. Maybe some clever way to get around this?
}

uint64_t clflush(uint64_t *addr, uint64_t __trash) {
    _mm_mfence(); 

    _mm_clflush(addr);

    return (__trash | (uint64_t)addr) & (MSB_MASK - 1);
}

int main(void) {

    #define OFFSET_TARGET 16
    #define OFFSET_EVICT 16

    int __trash = 0; 

    // mmap a specific memory address 
    char *line = mmap(0x666666a00000, 4096, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_POPULATE,
			     -1, 0 );
    line = line + OFFSET_TARGET;

    // L1 eviction set 
    #define STRIDE 131072
    // #define STRIDE 4096
    // #define STRIDE 8192
    #define TRIALS 10000
    #define EVICT_SIZE 4096
    uint64_t data_atck[TRIALS];
    uint64_t data_base[TRIALS];
    for(uint64_t L1_EVICT_SIZE = 0; L1_EVICT_SIZE < EVICT_SIZE; L1_EVICT_SIZE++) {
        char *l1_evict_original = mmap(0x555555500000, STRIDE * L1_EVICT_SIZE + 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_POPULATE,
                        -1, 0 );
        char *l1_evict = l1_evict_original + OFFSET_EVICT;
        for(int i = 0; i < L1_EVICT_SIZE; i++) // init 
                *(l1_evict + i * STRIDE) = rand() & (MSB_MASK - 1);

        // data collection 
        for(int i = 0; i < TRIALS; i++) {
            *line = ((*line | 0xdeadbeef) & (MSB_MASK - 1)); 
            _mm_mfence(); 
            data_base[i] = time_access(line, __trash);
            _mm_mfence();
            asm("nop\nnop\nnop\nnop\n" ::: "cc");
            for(int j = 0; j < L1_EVICT_SIZE; j++) // access L1 evict set 
                *(l1_evict + j * STRIDE) = (*(l1_evict + j * STRIDE) & MSB_MASK); 
            asm("nop\nnop\nnop\nnop\n" ::: "cc");
            _mm_mfence();
            data_atck[i] = time_access(line, __trash); 
            _mm_mfence();
        }
        fprintf(stderr, "L1_EVICT_SIZE %d\n", L1_EVICT_SIZE);
        for(int i = 0; i < TRIALS; i++) fprintf(stderr, "%d ", data_base[i]);
        fprintf(stderr, "\n");
        for(int i = 0; i < TRIALS; i++) fprintf(stderr, "%d ", data_atck[i]);
        fprintf(stderr, "\n");

        // free 
        munmap(0x555555500000, STRIDE * L1_EVICT_SIZE + 4096);
    }


    // // evict to memory 
    // #define L1_EVICT_SIZE 589824
    // // #define STRIDE 262144
    // #define STRIDE 64

    return 1; 
}