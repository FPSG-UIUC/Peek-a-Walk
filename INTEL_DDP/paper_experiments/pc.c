#include "../util/util.h"
#include <sys/mman.h>
#include "../bunnyhop/bunnyhop.h"

/* Gen macros */
#define PAGESIZE (4096)
#define TRIALS 10000


int main(int argc, char **argv) {

    if(argc != 3) {
        fprintf(stderr, "Error Usage: ./pc.out <pc train relative addr> <pc test offset>\n");
        exit(1);
    }

    uint64_t pc_train_relative = atoi(argv[1]);
    uint64_t pc_test_offset = atoi(argv[2]);
    uint64_t test_ptr_offset = 15 + 1; 
    uint64_t training_size = 350; 

    /* Gate to ensure we don't map the same memory */
    assert(pc_test_offset > 4120 && "Testing location too close to the train location, collision!");

    /* Init Ourselves */
    uint64_t __trash = 0; 
    pin_cpu(5);
    __trash = c_sleep(3000, __trash);
    _mm_mfence();

    /* Creating the training aop */
    uint64_t buffer_size = 1<<20; 
    uint64_t *training_buffer = malloc(sizeof(uint64_t) * buffer_size * 8);
    for(uint64_t i = 0; i < buffer_size * 8; i+=8) 
        training_buffer[i] = rand();
    uint64_t **training_aop = malloc(sizeof(uint64_t *) * training_size + 100 + MB(2));
    training_aop = (uint64_t *)((MB(2) - ((uint64_t)training_aop % MB(2))) + (char *)training_aop);
    assert((uint64_t)training_aop % MB(2) == 0); // align to 2 MB
    for(int i = 0; i < training_size + 1; i++) 
        training_aop[i] = &training_buffer[(rand() % buffer_size) * 8];

    /* ensure the test_buffer is far away from anything allocated by training */
    volatile uint64_t *guard_page = malloc(MB(2) * sizeof(uint64_t)); 
    for(int i = 0; i < MB(2); i += 4096)
        guard_page[i] = rand(); 

    /* Creating the test aop */
    uint64_t test_size = 100; 
    uint64_t *test_buffer = malloc(sizeof(uint64_t) * buffer_size * 8);
    for(uint64_t i = 0; i < buffer_size * 8; i+=8) 
        test_buffer[i] = rand();
    uint64_t **test_aop = malloc(sizeof(uint64_t *) * test_size + MB(2));
    test_aop = (uint64_t *)((MB(2) - ((uint64_t)test_aop % MB(2))) + (char *)test_aop);
    assert((uint64_t)test_aop % MB(2) == 0); // align to 2 MB
    for(int i = 0; i < test_size; i++) 
        test_aop[i] = &test_buffer[(rand() % buffer_size) * 8];

    /* ensure the ptr_under_test is far away from anything allocated by test_aop */
    volatile uint64_t *guard_page2 = malloc(MB(2) * sizeof(uint64_t)); 
    for(int i = 0; i < MB(2); i += 4096)
        guard_page[i] = rand(); 

    /* create ptr_under_test */
    volatile uint64_t *ptr_under_test = malloc(sizeof(uint64_t) * 32); 
    ptr_under_test = (uint64_t *)((64 - ((uint64_t)ptr_under_test % 64)) + (char *)ptr_under_test);
    assert((uint64_t)ptr_under_test % 64 == 0); // align to cache line 
    *ptr_under_test = 0xdeadbeef; 
    test_aop[test_ptr_offset] = ptr_under_test; 

    /* Create the train and test function */
    bhfunc bh_train = gen_access_aop(CONVERT_TO_TRAIN_LOAD_ADDR(DEFAULT_BASE + pc_train_relative), 150); 
    if((void *)bh_train == MAP_FAILED) {
        fprintf(stderr, "gen bh_train failed!\n");
        exit(1);
    }
    // bhfunc_load bh_trigger = gen_access_aop(CONVERT_TO_LOAD_ADDR(DEFAULT_BASE + pc_train_relative + pc_test_offset), 150); 
    bhfunc_load bh_trigger = gen_test_load(CONVERT_TO_TRIGGER_LOAD_ADDR(DEFAULT_BASE + pc_train_relative + pc_test_offset), 150); 
    if((void *)bh_trigger == MAP_FAILED) {
        fprintf(stderr, "gen bh_trigger failed!\n");
        exit(1);
    }

    /* Calm down */
    sleep(0); 

    /* Main loop */
    uint64_t times[TRIALS] = {0}; 
    for(int i = 0; i < TRIALS; i++) {
        /* maybe kill DDP? */ // TODO check if this actually does anything 
        sleep(0); 
        _mm_mfence(); 
        /* alternate between base and atck */
        
        test_aop[test_ptr_offset] = ptr_under_test; 
            
        _mm_mfence();  
        
        /* flush ptr_under_test */
        __trash = clflush(ptr_under_test, __trash);
        _mm_mfence(); 
        /* training */
        __trash = bh_train(training_aop, training_size, __trash, 1 /* stride */);
        _mm_mfence(); 
        /* activation */
        // __trash = bh_trigger(test_aop, 1 /* size 1 */, __trash, 1 /* stride */);
        bh_trigger(test_aop, 1);
        _mm_mfence(); 
        /* give DMP time to catch up */
        __trash = c_sleep(200, __trash);
        /* time access for atck */ 
        uint64_t trial_access_time = time_access(ptr_under_test, __trash);
        times[i] = trial_access_time;
    }

    /* output */ 
    for(int i = 0 ; i < TRIALS; i++)
        fprintf(stderr, "%lu ", times[i]); 
    fprintf(stderr, "\n");

    return 0; 
}