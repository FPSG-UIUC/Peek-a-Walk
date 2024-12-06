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
void evict_shuffle(int *array, size_t n) {
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
    for(uint64_t i = 0; i < size; i++)
        indexes[i] = i; 
    evict_shuffle(indexes, size); 
    return indexes; 
}

uint64_t c_sleep(uint64_t duration, uint64_t __trash) {
    // mulitplication to drive up time 
    __trash = __trash & MSB_MASK; // __trash = 0 
    for(uint64_t i = 1; i < (duration | (__trash & MSB_MASK)); i++) 
        __trash = (__trash * duration * i) & MSB_MASK; 
    return __trash; 
}

void pin_cpu(size_t core_ID) {
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(core_ID, &set);
	if (sched_setaffinity(0, sizeof(cpu_set_t), &set) < 0) {
		printf("Unable to Set Affinity\n");
		exit(EXIT_FAILURE);
	}

	// Set the scheduling priority to high to avoid interruptions
	// (lower priorities cause more favorable scheduling, and -20 is the max)
	setpriority(PRIO_PROCESS, 0, -20);
}

uint64_t bit_accuracy_checker(uint64_t guess, uint64_t correct) {
    uint64_t correct_levels = (VPN1_TO_CACHE_LINE(guess) == VPN1_TO_CACHE_LINE(correct)) + (VPN2_TO_CACHE_LINE(guess) == VPN2_TO_CACHE_LINE(correct)) + (VPN3_TO_CACHE_LINE(guess) == VPN3_TO_CACHE_LINE(correct)) + (VPN4_TO_CACHE_LINE(guess) == VPN4_TO_CACHE_LINE(correct)) + (PO_TO_CACHE_LINE(guess) == PO_TO_CACHE_LINE(correct));

#ifdef DEBUG
    fprintf(stderr, "Guess: 0x%llx\t\tCorrect: 0x%llx\n", guess, correct);
    fprintf(stderr, "Correct levels: %llu\n", correct_levels);
    fprintf(stderr, "\t\t\t\tTop Bits         VPN4      VPN3      VPN2      VPN1      PO\n");
    fprintf(stderr, "guess in binary: \t\t");
    for(int i = 63; i >= 0; i--) {
        fprintf(stderr, "%d", !!((1UL<<i) & guess));
        if(i == 48 || i == 39 || i == 30 || i == 21 || i == 12) fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "correct in binary: \t\t");
    for(int i = 63; i >= 0; i--) {
        fprintf(stderr, "%d", !!((1UL<<i) & correct));
        if(i == 48 || i == 39 || i == 30 || i == 21 || i == 12) fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
#endif

    uint64_t correct_bits = 0; 
    for(int i = 0; i < 64; i++) {
        uint64_t mask = (1UL<<i); 
        if((guess & mask) == (correct & mask))
            correct_bits++; 
    }
    return correct_bits; 
}
