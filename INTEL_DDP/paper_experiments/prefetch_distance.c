#include "../util/util.h"
#include "../bunnyhop/bunnyhop.h"
#include <sys/mman.h>

/* Gen macros */
#define PAGESIZE (4096)
#define TRIALS 10000

/* BH items */
extern bhfunc training_gadget;
extern bhfunc_load load_gadget_ddp; 
extern uint64_t **training_aop; 
extern uint64_t *test_aop;
extern uint64_t *garbage_aop;

/* GLOBAL DDP RESET ITEMS */
extern bhfunc ddp_eviction_gadgets[NUM_DDP_EVICTION_ITEMS];
extern uint64_t *ddp_eviction_aop[NUM_DDP_EVICTION_ITEMS];

int main(int argc, char **argv) {

    // args 
    if(argc != 4) {
        fprintf(stderr, "Error Usage: ./training_len.out <access size> <test ptr> <test_stride>\n");
        exit(1);
    }
    uint64_t access_size = atoi(argv[1]);
    int test_ptr = atoi(argv[2]);
    int stride = atoi(argv[3]);

    fprintf(stderr, "%lu %d %d\n", access_size, test_ptr, stride);

    /* Init Ourselves */
    uint64_t __trash = 0; 
    pin_cpu(5);
    __trash = c_sleep(3000, __trash);
    _mm_mfence();
    init_bunnyhop(0);

    // create our own test_aop 
    int true_stride = stride; 
    if(stride < 0) stride = stride * -1; 

    uint64_t n_train = 350;
    uint64_t train_aop_len = n_train * stride;
    uint64_t **big_aop = malloc(sizeof(uint64_t *) * train_aop_len);
    for(uint64_t i = 0; i < train_aop_len; i++)
        big_aop[i] = training_aop[rand() % TRAINING_SIZE];
    training_aop = big_aop;

    uint64_t test_aop_size = max((test_ptr < 0 ? -1 * test_ptr : test_ptr)+1, access_size * stride); 
    test_aop = malloc(sizeof(uint64_t) * test_aop_size + MB(2));
    test_aop = (uint64_t *)((KB(256) - ((uint64_t)test_aop % KB(256))) + (char *)test_aop); // align 
    assert((uint64_t)test_aop % KB(256) == 0); 
    test_aop += KB(32) + KB(16) + 1; // give it distance 
    for(int i = 0; i < test_aop_size; i++)
        test_aop[i] = rand(); 
    for(int i = 0; i < KB(32); i++)
        test_aop[-1 * i] = rand(); 


    fprintf(stderr, "ADDR: %lu %lu. Train aop: %p test_aop %p\n", (uint64_t) test_aop % MB(1), (uint64_t)(test_aop + 1) % MB(1), training_aop, test_aop);

    // create flag
    volatile uint64_t *ptr_under_test = malloc(sizeof(uint64_t)); 
    *ptr_under_test = 0xdeadbeef; 
    test_aop[test_ptr] = ptr_under_test; 

    // clean state 
    sleep(0); 

    /* Main loop */
    uint64_t times[TRIALS] = {0}; 
    for(int i = 0; i < TRIALS; i++) {

        // training 
        __trash = training_gadget(training_aop, n_train, __trash, stride);
        _mm_mfence(); 

        // clear flag 
        __trash = clflush(ptr_under_test, __trash);
        _mm_mfence(); 

        // test for training
        int idx = 0; 
        for(int i = 0; i < access_size; i++) {
            _mm_mfence(); 
            load_gadget_ddp(test_aop + idx, 1); 
            idx += true_stride; 
        }
        asm volatile("");
        __trash = c_sleep(1000, __trash);

        // time 
        times[i] = time_access(ptr_under_test, __trash);
    }

    // output 
    for(int i = 0 ; i < TRIALS; i++)
        fprintf(stderr, "%lu ", times[i]); 
    fprintf(stderr, "\n");
    return 0; 
}