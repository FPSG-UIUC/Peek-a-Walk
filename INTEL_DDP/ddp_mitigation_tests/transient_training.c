#include "../util/util.h"
#include <sys/mman.h>

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

// __attribute__((noinline))
// uint64_t access_aop1(uint64_t* aop, uint64_t size, uint64_t __trash) {
//     uint64_t aop_idx = 0;
//     for(int j = 0; j < size; j++) { // TODO maybe craft custom loop to improve transient window 
//         __trash = (__trash + j + aop_idx) & MSB_MASK;
//         asm(
//             "mov %1, %%r11\n"
//             "mov %2, %%r12\n"
//             "mov $0, %%rax\n"
//             "nop\nnop\nnop\nnop\nnop\nnop\nnop\n"
//             "mov (%%r11, %%r12, 8), %%rax\n"
//             "or (%%rax), %0\n" 
//             : "=r" (__trash)
//             : "r" (aop), "r" (aop_idx), "0" (__trash)
//             : "cc", "rax", "r10", "r11", "r12");
//         aop_idx += 1 | (__trash & MSB_MASK);
//     }
//     return __trash;
// }

__attribute__((noinline))
uint64_t access_aop1(uint64_t* aop, uint64_t size, uint64_t __trash) {
    asm(    
        "xor %%r12, %%r12\n"
        "mov %1, %%r11\n"
        "1:\n"

        "mov (%%r11, %%r12, 8), %%rax\n"
        "or (%%rax), %0\n" 

        // "add %%r12, %0\n"
        // "and %4, %0\n"
        // "lfence\n"

        "inc %%r12\n"
        "cmp %3, %%r12\n"
        "jl 1b\n"
        : "=r" (__trash)
        : "r" (aop), "0" (__trash), "r" (size)
        : "cc", "r11", "r12", "rax"
    );
    return __trash & MSB_MASK;
}


/* 
    SELF MODIFYING CODE HELPER FUNCTIONS 
    Taken from: https://stackoverflow.com/a/43162641
*/
int change_page_permissions_of_address(void *addr) {
    // Move the pointer to the page boundary
    int page_size = getpagesize();
    addr -= (unsigned long)addr % page_size;

    if(mprotect(addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        return -1;
    }

    return 0;
}

#define OFFSET 8
// #define OFFSET 61

__attribute__((always_inline))
void set_to_none_inst(void) { // refill with nops
    unsigned char *instruction = (unsigned char*)access_aop1 + OFFSET;
    *(instruction + 0) = 0x90;
    *(instruction + 1) = 0x90;
    *(instruction + 2) = 0x90;
    *(instruction + 3) = 0x90;
    *(instruction + 4) = 0x90; 
    *(instruction + 5) = 0x90; 
    *(instruction + 6) = 0x90; 
}

__attribute__((always_inline))
void set_to_mov_and_deref_inst(void) { // sets PC of access_aop1 to mov instruction
    unsigned char *instruction = (unsigned char*)access_aop1 + OFFSET;
    *(instruction + 0) = 0x4b;
    *(instruction + 1) = 0x8b;
    *(instruction + 2) = 0x04;
    *(instruction + 3) = 0xe3;
    *(instruction + 4) = 0x48;
    *(instruction + 5) = 0x0b; 
    *(instruction + 6) = 0x10;
}

__attribute__((always_inline))
void set_to_just_mov_inst(void) { // sets PC of access_aop1 to mov instruction
    unsigned char *instruction = (unsigned char*)access_aop1 + OFFSET;
    *(instruction + 0) = 0x4b;
    *(instruction + 1) = 0x8b;
    *(instruction + 2) = 0x04;
    *(instruction + 3) = 0xe3;
    *(instruction + 4) = 0x90; // nop
    *(instruction + 5) = 0x90; // nop
    *(instruction + 6) = 0x90; // nop
}

void read_inst(void) { // reads what instruction is at that address 
    unsigned char *instruction = (unsigned char*)access_aop1 + OFFSET;
    printf("0x%x%x%x%x\n", *instruction, *(instruction + 1), *(instruction + 2), *(instruction + 3));
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

    // thrash size minimum 400 
    thrash_size = max(thrash_size, 400);

    // pin to pcore 
    pin_cpu(core_id); 

    // set up seed
    uint64_t thrash_seed = 12, target_seed = 10;

    // setup aop buffer streams 
    uint64_t aop_conf_size = thrash_size; 
    uint64_t *aop_conf = malloc(sizeof(uint64_t) * (aop_conf_size+1024) + MB(2)); 
    for(int i = 0; i < aop_conf_size; i++) 
        aop_conf[i] = rand() & (MSB_MASK - 1); 
    aop_conf = (uint64_t *)((MB(2) - ((uint64_t)aop_conf % MB(2))) + (char *)aop_conf); 
    assert((uint64_t)aop_conf % MB(2) == 0);

    uint64_t aop_conf_thrash_size = confidence_thrash_size; 
    uint64_t *aop_conf_thrash = malloc(sizeof(uint64_t) * (aop_conf_thrash_size+1024) + MB(2)); 
    for(int i = 0; i < aop_conf_thrash_size; i++) 
        aop_conf_thrash[i] = rand() & (MSB_MASK - 1); 
    aop_conf_thrash = (uint64_t *)((MB(2) - ((uint64_t)aop_conf_thrash % MB(2))) + (char *)aop_conf_thrash); 
    assert((uint64_t)aop_conf_thrash % MB(2) == 0);

    SETUP_AOP(target_aop);
    SETUP_DATA_BUFFER(data_buffer_conf);
    SETUP_DATA_BUFFER(data_buffer_conf_thrash);
    SETUP_DATA_BUFFER(target_data_buffer);

    // set up thrash buffers 
    for(int i = 0; i < thrash_size; i++) { // set up additional pointers if necessary for initial flush 
        srand(thrash_seed + (i * (unique_thrash_ptr)));
        aop_conf[i] = (uint64_t)&data_buffer_conf[(rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE];
    }
    for(int i = 0; i < max(confidence_thrash_size, 1024); i++) {
        srand(thrash_seed + (i * (unique_thrash_ptr)));
        aop_conf_thrash[i] = (uint64_t)&data_buffer_conf_thrash[(rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE];
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

    // print out the entire target AOP 
    // srand(target_seed); 
    // for(int i = 0; i < num_diff_ptrs + (target_aop_size - training_size); i++) {
    //     _mm_lfence(); 
    //     asm("nop\nnop\nnop\n" :::"cc");
    //     uint64_t idx = (rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE;
    //     asm("lea (%1, %2, 8), %0\n"
    //         : "=r" (ptr_under_test)
    //         : "r" (target_data_buffer), "r" (idx)
    //         : "cc");
    //     asm("nop\nnop\nnop\n" :::"cc");
    // }
    // target_aop[target_aop_size - 1] = ((uint64_t)ptr_under_test);
    // for(int i = 0; i < target_aop_size; i++) {
    //     printf("%d\t\t%d\t%p\n", i, (target_aop[i] - (uint64_t)target_data_buffer), target_aop[i]);
    // }

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

    // set correct permissions
    void *addr_to_fix_permissions = (void*)access_aop1;
    if(change_page_permissions_of_address(addr_to_fix_permissions) == -1) {
        printf("Permission fixing failed!\n");
        exit(1);
    }

    // warm up the cache 
    for(int i = 0; i < 10; i++) 
        __trash = access_aop1(aop_conf, thrash_size, __trash);

    // thrash ddp state 
    // __trash = thrash_ddp_confidence_table(aop_conf_thrash, data_buffer_conf_thrash, 1024, __trash);
    sleep(0); 

    // train 
    uint64_t atk[repititions];
    uint64_t base[repititions];
    int mode = 0;
    int base_mode = 0; 
    for(int k = 0; k < repititions * 2; k++) {

        // reset to mov 
        set_to_mov_and_deref_inst();  

        _mm_mfence(); 
        _mm_lfence();

        // setup target pointer
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

        // thrash confidence table + training DMP
        sleep(0);
        // __trash = thrash_ddp_confidence_table(aop_conf_thrash, data_buffer_conf_thrash, confidence_thrash_size, __trash); // confidence table thrash
        _mm_mfence(); 
        _mm_lfence(); 
        for(int i = 0; i < 10; i++) { // training on 400 pointers 
            for(int j = 0; j < 16; j++) asm("imul $1, %%r11" :::"cc", "r11"); // make store slow (taken from example code)
            set_to_none_inst(); // transient window  
            __trash = access_aop1(aop_conf + (i * 40), 40, __trash); // training
            _mm_mfence(); 
            _mm_lfence(); 
            set_to_mov_and_deref_inst(); 
            _mm_mfence(); 
            _mm_lfence(); 
        }
        set_to_just_mov_inst(); // just mov instruction 
        __trash = clflush(ptr_under_test, __trash);

        _mm_mfence(); 
        _mm_lfence();

        // sleep 
        __trash = c_sleep(1500, __trash);

        // train 
        __trash = access_aop1(target_aop, training_size, __trash); // test 

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
