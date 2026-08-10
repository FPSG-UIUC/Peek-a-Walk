#include "../util/util.h"
#include <sys/mman.h>

/* Gen macros */
#define PAGESIZE (4096)
#define TRIALS 10000

/* Training / Testing gadget */
__attribute__((noinline))
uint64_t access_aop(uint64_t *aop, uint64_t size, uint64_t consumer_load_bit, uint64_t __trash) {
    asm volatile(    
        "xor %%r12, %%r12\n"
        "xor %%r13, %%r13\n"
        "xor %%rbx, %%rbx\n"
        "mov %1, %%r11\n"

        "1:\n"
        "mov (%%r11, %%r12, 8), %%rax\n" 
        "cmp $1, %4\n"
        "jne 2f\n"
        "mfence\n" // spec barrier 
        // "or (%%rbx, %%rax), %0\n" 
        "or (%%rax), %0\n" 

        "2:\n"
        "add $1, %%r12\n" // stride 
        "add $1, %%r13\n" // size
        "cmp %3, %%r13\n"

        "jl 1b\n"
        : "=r" (__trash)
        : "r" (aop), "0" (__trash), "r" (size), "r" (consumer_load_bit)
        : "cc", "r11", "r12", "r13", "rax", "rbx"
    );
    return __trash & MSB_MASK;
}

int main(int argc, char **argv) {

    if(argc != 3) {
        fprintf(stderr, "Error Usage: ./fixed.out <training size> <flush_enable>\n");
        exit(1);
    }

    uint64_t training_size = atoi(argv[1]);
    uint64_t test_ptr_offset = 16;
    uint64_t flush_en = atoi(argv[2]);

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
    uint64_t **training_aop = (uint64_t **) mmap ( (void*)(0x666700000000UL), sizeof(uint64_t *) * training_size + 100 + MB(2), 
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE,
			     -1, 0 );
    // training_aop = (uint64_t *)((MB(2) - ((uint64_t)training_aop % MB(2))) + (char *)training_aop);
    assert((uint64_t)training_aop % MB(2) == 0); // align to 2 MB
    for(int i = 0; i < training_size + 1; i++) 
        training_aop[i] = &training_buffer[(rand() % buffer_size) * 8];

    /* ensure the test_buffer is far away from anything allocated by training */
    volatile uint64_t *guard_page = malloc(MB(2) * sizeof(uint64_t)); 
    for(int i = 0; i < MB(2); i += 4096)
        guard_page[i] = rand(); 

    /* Creating the test aop */
    uint64_t test_size = 100; 
    uint64_t *test_buffer = (uint64_t *) mmap ( (void*)(0x666800000000UL), sizeof(uint64_t) * buffer_size * 8, 
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE,
			     -1, 0 );
    for(uint64_t i = 0; i < buffer_size * 8; i+=8) 
        test_buffer[i] = rand();
    uint64_t **test_aop = (uint64_t **) mmap ( (void*)(0x666900000000UL), sizeof(uint64_t *) * test_size + MB(2), 
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE,
			     -1, 0 );
    // test_aop = (uint64_t *)((MB(2) - ((uint64_t)test_aop % MB(2))) + (char *)test_aop);
    assert((uint64_t)test_aop % MB(2) == 0); // align to 2 MB
    for(int i = 0; i < test_size; i++) 
        test_aop[i] = &test_buffer[(rand() % buffer_size) * 8];

    /* ensure the ptr_under_test is far away from anything allocated by test_aop */
    volatile uint64_t *guard_page2 = malloc(MB(2) * sizeof(uint64_t)); 
    for(int i = 0; i < MB(2); i += 4096)
        guard_page[i] = rand(); 

    /* create ptr_under_test */
    volatile uint64_t *ptr_under_test = mmap(0x667000000000UL, 4096, 
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE,
			     -1, 0 );
    // ptr_under_test = (uint64_t *)((64 - ((uint64_t)ptr_under_test % 64)) + (char *)ptr_under_test);
    assert((uint64_t)ptr_under_test % 64 == 0); // align to cache line 
    *ptr_under_test = 0xdeadbeef; 
    test_aop[test_ptr_offset] = ptr_under_test; 

    /* Calm down */
    sleep(0); 

    /* Main loop */
    uint64_t times[TRIALS] = {0}; 
    for(int i = 0; i < TRIALS * 2; i++) {
        _mm_mfence(); 
        
        /* flush the training aop */
        if (flush_en) {
            _mm_mfence();
            for(int j = 0; j < training_size; j++) {
                _mm_mfence();
                __trash = clflush(training_aop[j], __trash);
                __trash = clflush(training_aop + j, __trash);
            }
            __trash = usleep(0); //flush DMP state since there's double-dereferences during flushing, look at syscall.c
            _mm_mfence();
            /* give DMP state time to catch up */
            __trash = c_sleep(500, __trash);
            _mm_mfence();
        }
        _mm_mfence();  

        /* alternate between base and atck */
        if( i % 2 )
            test_aop[test_ptr_offset] = ptr_under_test; 
        else 
            test_aop[test_ptr_offset] = NULL; 
            
        /* flush ptr_under_test */
        __trash = clflush(ptr_under_test, __trash);
        _mm_mfence(); 

        /* training */
        __trash = access_aop(training_aop, training_size, 1, __trash);
        _mm_mfence(); 

        /* activation, one single time */
        __trash = access_aop(test_aop, 1 /* size 1 */, 0, __trash);
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

    // compute an average 
    uint64_t sum = 0; 
    uint64_t cnt = 0; 
    for(int i = 0 ; i < TRIALS; i++)
        if(times[i] < 100UL) {
            sum += times[i]; 
            cnt++; 
        }
    fprintf(stderr, "Average: %f\n", (sum * 1.0) / (cnt * 1.0));

    return 0; 
}