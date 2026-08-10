#include "util.h"

uint64_t time_access(uint64_t *addr, uint64_t __trash) {
    uint64_t T0, T1, time;

    // enforce ordering 
    _mm_mfence();
    _mm_lfence();

    // measuring timing
    T0 = __rdtscp( (unsigned int *)&__trash ); 

    // serialize the rdtscp 
    _mm_lfence();

    __trash = *addr; 

    // serialize the rdtscp
    _mm_lfence();

    // measuring timing 
    T1 = __rdtscp( (unsigned int *)&__trash ); 

    // serialize 
    _mm_lfence();
    time = T1 - T0; 

    // noise measurements 
    _mm_mfence();
    _mm_lfence();
    T0 = __rdtscp( (unsigned int *)&__trash ); 
    _mm_lfence();
    _mm_lfence();
    T1 = __rdtscp( (unsigned int *)&__trash ); 
    _mm_lfence();

    // subtract out noise
    return (time - (T1 - T0)) | (__trash & MSB_MASK); // TODO this sneaks an extra AND call into the timing measurement. Maybe some clever way to get around this?
}

uint64_t clflush(uint64_t *addr, uint64_t __trash) {
    _mm_mfence(); 

    _mm_clflush(addr);

    return (__trash | (uint64_t)addr) & (MSB_MASK - 1);
}

/* Arrange the N elements of ARRAY in random order.
   Only effective if N is much smaller than RAND_MAX;
   if this may not be the case, use a better random
   number generator. */
// Taken from: https://stackoverflow.com/a/6127606
void shuffle(int *array, size_t n) {
    if (n > 1) 
    {
        size_t i;
        for (i = 0; i < n - 1; i++) 
        {
          size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
          int t = array[j];
          array[j] = array[i];
          array[i] = t;
        }
    }
}

int* generate_indexes(uint64_t size) {
    int* indexes = calloc(1, sizeof(int) * size); 
    for(int i = 0; i < size; i++)
        indexes[i] = i; 
    shuffle(indexes, size); 
    return indexes; 
}

uint64_t c_sleep(uint64_t duration, uint64_t __trash) {
    // mulitplication to drive up time 
    __trash = __trash & MSB_MASK; // __trash = 0 
    for(int i = 1; i < (duration + 1 | (__trash & MSB_MASK)); i++) 
        __trash = (__trash * duration * i) & MSB_MASK; 
    return __trash; 
}