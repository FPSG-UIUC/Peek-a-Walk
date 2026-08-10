#include "../util/util.h"
#include <sys/mman.h>

/* Gen macros */
#define PAGESIZE (4096)
#define TRIALS 10000

/* Training / Testing gadget */
__attribute__((noinline))
uint64_t access_aop(uint64_t *buf, uint64_t *indexes, uint64_t size, uint64_t consumer_load_bit, uint64_t __trash) {
    asm volatile(    
        "xor %%r12, %%r12\n"
        "xor %%r13, %%r13\n"
        "xor %%rbx, %%rbx\n"

        "1:\n"
        "mov (%2, %%r12, 8), %%rax\n"  // get index 
        "cmp $1, %5\n"
        "jne 2f\n"
        "mfence\n" // spec barrier 
        "or (%1, %%rax, 8), %0\n"  // buf[index]

        "2:\n"
        "add $1, %%r12\n" // stride 
        "add $1, %%r13\n" // size
        "cmp %4, %%r13\n"

        "jl 1b\n"
        : "=r" (__trash)
        : "r" (buf), "r" (indexes), "0" (__trash), "r" (size), "r" (consumer_load_bit)
        : "cc", "r11", "r12", "r13", "rax", "rbx"
    );
    return __trash & MSB_MASK;
}

int main(int argc, char **argv) {

    if(argc != 3) {
        fprintf(stderr, "Error Usage: ./indirect.out <training size> <test ptr offset>\n");
        exit(1);
    }

    uint64_t training_size = atoi(argv[1]);
    uint64_t test_ptr_offset = atoi(argv[2]);

    /* Init Ourselves */
    uint64_t __trash = 0; 
    pin_cpu(5);
    __trash = c_sleep(3000, __trash);
    _mm_mfence();

    /* Creating the training aop */
    uint64_t buffer_size = 1<<20;
    uint64_t *training_buffer = (uint64_t *) mmap ( (void*)(0x666600000000UL), sizeof(uint64_t) * buffer_size * 8, 
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE,
			     -1, 0 );
    for(uint64_t i = 0; i < buffer_size * 8; i+=8) 
        training_buffer[i] = rand();
    uint64_t *training_idx = (uint64_t **) mmap ( (void*)(0x666700000000UL), sizeof(uint64_t *) * training_size + 100 + MB(2), 
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE,
			     -1, 0 );
    // training_aop = (uint64_t *)((MB(2) - ((uint64_t)training_aop % MB(2))) + (char *)training_aop);
    assert((uint64_t)training_idx % MB(2) == 0); // align to 2 MB
    for(int i = 0; i < training_size + 1 + test_ptr_offset - 1; i++) 
        training_idx[i] = 8*(rand() % buffer_size);  // make sure each is on a unique cache line 
    
    // set ptr_under_test idx
    uint64_t index_under_test = 8*(rand() % buffer_size);
    training_idx[training_size + test_ptr_offset] = index_under_test; 

    /* create ptr_under_test */
    volatile uint64_t *ptr_under_test = &training_buffer[training_idx[training_size + test_ptr_offset]]; 
    // ptr_under_test = (uint64_t *)((64 - ((uint64_t)ptr_under_test % 64)) + (char *)ptr_under_test);
    assert((uint64_t)ptr_under_test % 64 == 0); // align to cache line 
    *ptr_under_test = 0xdeadbeef; 

    /* Calm down */
    sleep(0); 

    /* Main loop */
    uint64_t times[TRIALS] = {0}; 
    for(int i = 0; i < TRIALS * 2; i++) {
        
        /* Kill the DMP */
        __trash = access_aop(training_buffer, training_idx, 20, 0, __trash);
        _mm_mfence(); 
        
        /* flush the training aop */
        for(int j = 0; j < training_size; j++) {
            __trash = clflush(&training_buffer[training_idx[j]], __trash);
            __trash = clflush(&training_idx[j], __trash);
        }
        _mm_mfence();  

        /* alternate between base and atck */
        if( i % 2 )
            training_idx[training_size + test_ptr_offset] = index_under_test; 
        else 
            training_idx[training_size + test_ptr_offset] = NULL; 
            
        /* flush ptr_under_test */
        __trash = clflush(ptr_under_test, __trash);
        _mm_mfence(); 

        /* training + activation */
        __trash = access_aop(training_buffer, training_idx, training_size, 1, __trash);
        _mm_mfence(); 

        /* give DMP time to catch up */
        __trash = c_sleep(200, __trash);

        /* time access for atck OR ensure no hits in base */ 
        uint64_t trial_access_time = time_access(ptr_under_test, __trash);
        if (i % 2)
            times[i/2] = trial_access_time;
        else 
            assert(trial_access_time > 100 && "Base mode registered a hit of the ptr_under_test!");
    }

    /* output */ 
    for(int i = 0 ; i < TRIALS; i++)
        fprintf(stderr, "%lu ", times[i]); 
    fprintf(stderr, "\n");

    return 0; 
}