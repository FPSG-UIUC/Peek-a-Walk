#include "../util/util.h"
#include <pthread.h> 

uint64_t core_id;
uint64_t repititions; 
uint64_t training_size; 
uint64_t test_ptr_after; 
uint64_t num_diff_ptrs;
uint64_t thrash_size;
uint64_t unique_thrash_ptr;
uint64_t confidence_thrash_size;
uint64_t sort_output;

#define ACCESS_AOP_CODE(name) \
    __attribute__((noinline)) \
    uint64_t name(uint64_t* aop, uint64_t size, uint64_t stride, uint64_t __trash, uint64_t *data_buffer) { \
        uint64_t aop_idx = 0; \
        for(int j = 0; j < size; j += stride) { \
            _mm_lfence(); \
            __trash = (__trash + j + aop_idx) & MSB_MASK; \
            asm("mov (%1, %2, 8), %%rax\nor (%%rax), %0\n" : "=r" (__trash) : "r" (aop), "r" (aop_idx), "0" (__trash), "r" (data_buffer) : "cc", "rax", "r10"); \
            aop_idx += 1 | (__trash & MSB_MASK); \
        } \
        return __trash; \
    }

__attribute__((noinline))
uint64_t access_aop1(uint64_t* aop, uint64_t size, uint64_t stride, uint64_t __trash, uint64_t *data_buffer, uint64_t deref_mode) {
    uint64_t aop_idx = 0;
    for(int j = 0; j < size; j += stride) {
        _mm_lfence();
        __trash = (__trash + j + aop_idx) & MSB_MASK;
        asm(
            // "jz .+18\n"
            "mov (%1, %2, 8), %%rax\n"
            "mov %0, %%r10\n"
            "cmp %5, %%r10\n"
            "jz .+8\n"
            "lfence\n"
            "or (%%rax), %0\n" 
            : "=r" (__trash)
            : "r" (aop), "r" (aop_idx), "0" (__trash), "r" (data_buffer), "r" (deref_mode) 
            : "cc", "rax", "r10");
        aop_idx += 1 | (__trash & MSB_MASK);
    }
    return __trash;
}


// ACCESS_AOP_CODE(access_aop1)
ACCESS_AOP_CODE(access_aop2)
ACCESS_AOP_CODE(access_aop3)
ACCESS_AOP_CODE(access_aop4)
ACCESS_AOP_CODE(access_aop5)
ACCESS_AOP_CODE(access_aop6)
ACCESS_AOP_CODE(access_aop7)
ACCESS_AOP_CODE(access_aop8)
ACCESS_AOP_CODE(access_aop9)
ACCESS_AOP_CODE(access_aop10)
ACCESS_AOP_CODE(access_aop11)
ACCESS_AOP_CODE(access_aop12)
ACCESS_AOP_CODE(access_aop13)
ACCESS_AOP_CODE(access_aop14)
ACCESS_AOP_CODE(access_aop15)
ACCESS_AOP_CODE(access_aop16)
ACCESS_AOP_CODE(access_aop17)
ACCESS_AOP_CODE(access_aop18)
ACCESS_AOP_CODE(access_aop19)
ACCESS_AOP_CODE(access_aop20)
ACCESS_AOP_CODE(access_aop21)
ACCESS_AOP_CODE(access_aop22)
ACCESS_AOP_CODE(access_aop23)
ACCESS_AOP_CODE(access_aop24)
ACCESS_AOP_CODE(access_aop25)
ACCESS_AOP_CODE(access_aop26)
ACCESS_AOP_CODE(access_aop27)
ACCESS_AOP_CODE(access_aop28)
ACCESS_AOP_CODE(access_aop29)
ACCESS_AOP_CODE(access_aop30)
ACCESS_AOP_CODE(access_aop31)
ACCESS_AOP_CODE(access_aop32)


// thrash the DDP confidence table (16 entries using PC tag)
__attribute__((noinline))
uint64_t thrash_ddp_confidence_table(uint64_t* aop1, uint64_t *data_buffer1, uint64_t aop_size, uint64_t __trash) {
    // make sure history is fresh (previous history can't affect us here)
    for(int i = 0; i < 2; i++) {
        _mm_lfence(); 
        __trash = access_aop2(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop3(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop4(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop5(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop6(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop7(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop8(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop9(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop10(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop11(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop12(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop13(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop14(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop15(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop16(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
        __trash = access_aop17(aop1, aop_size, 1, __trash, data_buffer1); // diff pc 
    }
    return __trash;
}

// stupid barrier
// int thread_start = 0; 

// thread 
void *thread_work(void *arg) {
    (void) arg; 

    // SMT siblings 
    // if(core_id % 2 == 0)  // pin to same physical core 
    //     pin_cpu(core_id + 1);
    // else 
    //     // pin_cpu(core_id + 8);
    //     pin_cpu(core_id - 1); 
    pin_cpu(core_id);

    uint64_t __trash = 0; 

    // setup items 
    uint64_t aop1_size = thrash_size; 
    uint64_t *aop1 = malloc(sizeof(uint64_t) * (aop1_size+1024) + MB(2)); 
    for(int i = 0; i < aop1_size; i++) 
        aop1[i] = rand() & (MSB_MASK - 1); 
    aop1 = (uint64_t *)((MB(2) - ((uint64_t)aop1 % MB(2))) + (char *)aop1); 
    SETUP_DATA_BUFFER(data_buffer1);

    // set up thrash buffers 
    for(int i = 0; i < max(thrash_size, max(confidence_thrash_size, 1024)); i++) { // set up additional pointers if necessary for initial flush 
        srand(12 + (i * (unique_thrash_ptr)));
        aop1[i] = (uint64_t)&data_buffer1[(rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE];
    }

    // stupid barrier to make sure nothing crazy 
    // while(!thread_start) { sched_yield(); }

    _mm_lfence(); // spec barrier 

    // training (cross thread context training )
    __trash = access_aop1(aop1, thrash_size, 1, __trash, data_buffer1, 1); // same pc (deref mode)
    // __trash = access_aop2(aop1, thrash_size, 1, __trash, data_buffer1); // same pc (deref mode)
    fprintf(stderr, "inside %d %p %d", thrash_size, access_aop1, getpid());

    return NULL;
}


int main(int argc, char **argv) {

    // arg parse
    if(argc != 10) {
        printf("Usage: ./table_re.out <core id> <repititions> <training size> <test_ptr_after> <num diff ptrs> <thrash size> <unique thrash ptrs?> <confidence thrash size> <sort output?>\n");
        exit(1);
    }
    core_id = atoi(argv[1]);
    repititions = atoi(argv[2]);
    training_size = atoi(argv[3]);
    test_ptr_after = atoi(argv[4]);
    num_diff_ptrs = atoi(argv[5]);
    thrash_size = atoi(argv[6]);
    unique_thrash_ptr = atoi(argv[7]);
    confidence_thrash_size = atoi(argv[8]);
    sort_output = atoi(argv[9]);

    printf("Experiment Setup:\n");
    printf("Core id: \t\t\t\t%lu\n", core_id);
    printf("repititions: \t\t\t\t%lu\n", repititions);
    printf("Training Size: \t\t\t\t%lu\n", training_size);
    printf("Ptr under test after training: \t\t%lu\n", test_ptr_after);
    printf("# Training ptr: \t\t\t%lu\n", num_diff_ptrs); // different # of training_ptr IF 0 then all pointers are the ptr_under_test
    printf("Thrash Size: \t\t\t\t%lu\n", thrash_size);
    printf("Unique Thrash ptr: \t\t\t%lu\n", unique_thrash_ptr);
    printf("Conf Thrash Size: \t\t\t%lu\n", confidence_thrash_size);
    printf("sort output: \t\t\t\t%lu\n", sort_output);

    // pin to pcore 
    pin_cpu(core_id); 

    // set up seed
    uint64_t thrash_seed = 12, target_seed = 10;

    // setup aop buffer streams 
    uint64_t aop1_size = thrash_size; 
    uint64_t *aop1 = malloc(sizeof(uint64_t) * (aop1_size+1024) + MB(2)); 
    for(int i = 0; i < aop1_size; i++) 
        aop1[i] = rand() & (MSB_MASK - 1); 
    aop1 = (uint64_t *)((MB(2) - ((uint64_t)aop1 % MB(2))) + (char *)aop1); 
    assert((uint64_t)aop1 % MB(2) == 0);
    SETUP_AOP(target_aop);
    SETUP_DATA_BUFFER(data_buffer1);
    SETUP_DATA_BUFFER(target_data_buffer);

    // set up thrash buffers 
    for(int i = 0; i < max(thrash_size, max(confidence_thrash_size, 1024)); i++) { // set up additional pointers if necessary for initial flush 
        srand(thrash_seed + (i * (unique_thrash_ptr)));
        aop1[i] = (uint64_t)&data_buffer1[(rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE];
    }

    // generate aop ptrs  
    uint64_t training_idx[num_diff_ptrs];
    srand(target_seed);
    for(int i = 0; i < num_diff_ptrs; i++)
        training_idx[i] = (rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE;

    // set up target buffers 
    uint64_t *ptr_under_test = NULL; 
    if(num_diff_ptrs > 0) {
        for(int i = 0; i < training_size; i++) 
            target_aop[i] = (uint64_t)&target_data_buffer[training_idx[i % num_diff_ptrs]];
        for(int i = training_size; i < target_aop_size - 1; i++)
            target_aop[i] = (uint64_t)&target_data_buffer[(rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE];
    } else {
        printf("Error, 0 training pointers makes no sense ...\n");
        return -1; 
    }

    // collect all pointers / duplicate pointer check
    srand(target_seed);
    uint64_t indexes[target_aop_size];
    for(int i = 0; i < target_aop_size; i++) {
       indexes[i] = (rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE; 
       assert(indexes[i] < target_data_buffer_size);
    }
    qsort( indexes, target_aop_size, sizeof(uint64_t), compare );  
    for(int i = 1; i < target_aop_size; i++) {
        if(indexes[i-1] == indexes[i]) {
            printf("Duplicate pointers\n");
            exit(1);
        }
    }

    // trash
    uint64_t __trash = 0; 

    // thrash ddp state 
    __trash = thrash_ddp_confidence_table(aop1, data_buffer1, 1024, __trash);

    // train 
    uint64_t atk[repititions];
    uint64_t base[repititions];
    int mode = 0;
    int base_mode = 0; 
    for(int k = 0; k < repititions * 2; k++) {
        _mm_mfence(); 
        _mm_lfence();

        srand(target_seed); 
        for(int i = 0; i < num_diff_ptrs + (target_aop_size - training_size); i++) {
            _mm_lfence(); 
            asm("nop\nnop\nnop\n" :::"cc");
            uint64_t idx = (rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE;
            asm("lea (%1, %2, 8), %0\n"
                : "=r" (ptr_under_test)
                : "r" (target_data_buffer), "r" (idx)
                : "cc");
            asm("nop\nnop\nnop\n" :::"cc");
        }
        target_aop[target_aop_size - 1] = ((uint64_t)ptr_under_test & mode);

        _mm_mfence(); 
        _mm_lfence();

        // thrash some table 
        __trash = thrash_ddp_confidence_table(aop1, data_buffer1, confidence_thrash_size, __trash); // confidence table thrash
        sleep(0);

        // start da thread which trains the DMP confidence entry 
        fprintf(stderr, "(");
        pthread_t tid;
        int status = pthread_create(&tid, NULL, thread_work, NULL);
        if(status != 0) {
            printf("thread start failure!\n");
            exit(1);
        }
        pthread_join(tid, NULL);
        _mm_mfence();
        _mm_lfence(); 
        fprintf(stderr, ") %p\n", access_aop1);

        // some point just need to touch an array a couple of times 
        // __trash = access_aop1(aop1, 1, 1, __trash, data_buffer1, 0); // we simply need to touch an array
        __trash = clflush(ptr_under_test, __trash);

        _mm_mfence(); 
        _mm_lfence();

        // train 
        __trash = access_aop1(target_aop, training_size, 1, __trash, target_data_buffer, 0); // deref mode optional :) 

        // _mm_mfence(); 
        // _mm_lfence();

        // sleep 
        __trash = c_sleep(1500, __trash);

        // _mm_mfence(); 
        // _mm_lfence();

        // measure 
        uint64_t test_time = time_access(ptr_under_test, __trash);
        __trash = (__trash | test_time) & MSB_MASK;

        // save
        if(mode == base_mode)
            base[k/2] = test_time; 
        else 
            atk[k/2] = test_time;
        // fprintf(stderr, "%lu ", test_time);

        mode = ~mode; 
    }

    // output 
    if(sort_output)
        qsort( atk, repititions, sizeof(uint64_t), compare );  
    // qsort( base, repititions, sizeof(uint64_t), compare );  
    printf("Base: ");
    for(int i = 0; i < repititions; i++) printf("%lu ", base[i]);
    printf("\n");
    printf("Atck: ");
    for(int i = 0; i < repititions; i++) printf("%lu ", atk[i]);
    printf("\n");
}
