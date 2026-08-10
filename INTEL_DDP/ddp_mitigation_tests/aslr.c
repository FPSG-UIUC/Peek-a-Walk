#include "../util/util.h"
#include "../bunnyhop/bunnyhop.h"
#include <sys/mman.h>

uint64_t core_id;
uint64_t repititions; 
uint64_t sort_output;

#define STRIDE_SETTER_BASE_ADDR (0x5ffffff00000)

__attribute__((noinline))
uint64_t my_access_aop(uint64_t* aop, uint64_t size, uint64_t __trash, uint64_t stride) {
    asm(    
        "xor %%r12, %%r12\n"
        "xor %%r13, %%r13\n"
        "mov %1, %%r11\n"
        "1:\n"

        "mov (%%r11, %%r12, 8), %%rax\n"
        "lfence\n" // improve training 
        // "or (%%rax), %0\n"

        "add %4, %%r12\n" // stride 
        "add $1, %%r13\n" // size
        "cmp %3, %%r13\n"

        "jl 1b\n"
        : "=r" (__trash)
        : "r" (aop), "0" (__trash), "r" (size), "r" (stride)
        : "cc", "r11", "r12", "r13", "rax"
    );
    return __trash & MSB_MASK;
}

#define OFFSET 13

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

__attribute__((always_inline))
void cause_spec(void) { // refill with nops
    unsigned char *instruction = (unsigned char*)my_access_aop + OFFSET;
    *(instruction + 0) = 0x90;
    *(instruction + 1) = 0x90;
    *(instruction + 2) = 0x90;
    *(instruction + 3) = 0x90;
    // *(instruction + 4) = 0x90;
    // *(instruction + 5) = 0x90;
    // *(instruction + 6) = 0x90;
    // *(instruction + 7) = 0x90;
    // *(instruction + 8) = 0x90;
    // *(instruction + 9) = 0x90;
}

__attribute__((always_inline))
void reset_inst(void) { // sets PC of access_aop1 to mov instruction
    unsigned char *instruction = (unsigned char*)my_access_aop + OFFSET;
    *(instruction + 0) = 0x4b;
    *(instruction + 1) = 0x8b;
    *(instruction + 2) = 0x04;
    *(instruction + 3) = 0xe3; 
    // *(instruction + 4) = 0x0f;
    // *(instruction + 5) = 0xae;
    // *(instruction + 6) = 0xe8;
    // *(instruction + 7) = 0x48;
    // *(instruction + 8) = 0x0b;
    // *(instruction + 9) = 0x10;
}

void read_inst(void) { // reads what instruction is at that address 
    unsigned char *instruction = (unsigned char*)my_access_aop + OFFSET;
    printf("0x%x%x%x%x\n", *instruction, *(instruction + 1), *(instruction + 2), *(instruction + 3));
}

int main(int argc, char **argv) {

    // arg parse
    if(argc != 4) {
        printf("Usage: ./aslr.out <core id> <reps> <sort output>?\n");
        exit(1);
    }
    core_id = atoi(argv[1]);
    repititions = atoi(argv[2]);
    sort_output = atoi(argv[3]);

    printf("Experiment Setup:\n");
    printf("Core id: \t\t\t\t%lu\n", core_id);
    printf("repititions: \t\t\t\t%lu\n", repititions);
    printf("sort output: \t\t\t\t%lu\n", sort_output);

    // pin to pcore 
    pin_cpu(core_id); 

    // set up seed
    srand(12);

    // set up target VA to determine is mapped? 
    uint64_t target_va_address_page = 0x7ffffff00000;
    uint64_t target_va_address_offset = 512;
    void *target_va = (void *) mmap( (void *)target_va_address_page, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_POPULATE, -1, 0 );
    if(target_va == NULL) {
        printf("BAD Target VA\n");
        exit(1);
    }
    target_va += target_va_address_offset; 
    *(uint64_t *)target_va = rand() & (MSB_MASK - 1);
    // munmap(target_va_address_page, 4096);

    // setup training aop
    SETUP_DATA_BUFFER(training_buffer);
    uint64_t training_stride = 2;
    uint64_t training_aop_size = 256;
    uint64_t *training_aop = malloc(sizeof(uint64_t) * training_aop_size * training_stride + MB(2)); 
    training_aop = (uint64_t *)((MB(2) - ((uint64_t)training_aop % MB(2))) + (char *)training_aop); 
    assert((uint64_t)training_aop % MB(2) == 0);
    for(int i = 0; i < training_aop_size * training_stride; i+=training_stride) { // set up additional pointers if necessary for initial flush 
        training_aop[i] = (uint64_t)&training_buffer[(rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE];
    }

    // setup stride setter 
    void *stride_setter_base = (void *) mmap( (void *)STRIDE_SETTER_BASE_ADDR, 1024 * 8 * 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_POPULATE, -1, 0 );
    if(stride_setter_base == NULL) {
        printf("Bad setter base\n");
        exit(1);
    }
    void *stride_setter_aop = (uint64_t)stride_setter_base + target_va_address_offset - 8; // want to set stride to 1
    *(uint64_t *)stride_setter_aop = rand() & (MSB_MASK - 1);
    // SETUP_DATA_BUFFER(stride_setter_buffer);
    // uint64_t stride_setter_aop_size = 1024 * 8 * 17; 
    // volatile uint64_t *stride_setter_aop = malloc(sizeof(uint64_t) * stride_setter_aop_size + MB(2));
    // stride_setter_aop = (uint64_t *)((MB(2) - ((uint64_t)stride_setter_aop % MB(2))) + (char *)stride_setter_aop); 
    // assert((uint64_t)stride_setter_aop % MB(2) == 0);
    // for(int i = 0; i < stride_setter_aop_size; i++) { // doesn't need to be ptrs 
    //     // stride_setter_aop[i] = rand() & (MSB_MASK - 1); 
    //     stride_setter_aop[i] = &stride_setter_buffer[(rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE];
    // }

    // setup test buffer
    uint64_t target_mask = ~0;
    SETUP_DATA_BUFFER(test_buffer);
    uint64_t target_aop_size = 1 + 16;
    uint64_t *target_aop = malloc(target_aop_size * sizeof(uint64_t)); 
    for(int i = 0; i < target_aop_size - 1; i++) 
        target_aop[i] = rand() & (MSB_MASK - 1); 
    uint64_t *ptr_under_test = &test_buffer[(rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE];
    target_aop[target_aop_size - 1] = ptr_under_test; 
    target_aop[0] = &test_buffer[(rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE];

    // trash
    uint64_t __trash = 0; 

    // set correct permissions
    void *addr_to_fix_permissions = (void*)my_access_aop;
    if(change_page_permissions_of_address(addr_to_fix_permissions) == -1) {
        printf("Permission fixing failed!\n");
        exit(1);
    }

    // create access_aop1 function
    uint64_t (*access_train)(uint64_t*, uint64_t, uint64_t, uint64_t) = gen_access_aop(COLLISION_FUNC_START(DEFAULT_BASE, (uint64_t)my_access_aop + 13), 300);
    uint64_t (*access_test)(uint64_t*, uint64_t, uint64_t, uint64_t) = my_access_aop; 

    // thrash ddp state 
    sleep(0); 

    // train 
    uint64_t atk[repititions];
    uint64_t base[repititions];
    int mode = 0;
    int base_mode = 0; 
    for(int k = 0; k < repititions * 2; k++) {  

        // setup mode
        target_aop[target_aop_size - 1] ^= target_mask; // made to be garbage 

        // thrash confidence table + training DMP
        sleep(0);

        // training 
        __trash = access_train(training_aop, training_aop_size, __trash, training_stride); // set stride to 2
        _mm_mfence();
        __trash = access_test(stride_setter_aop, 1, __trash, 1); // set up stride change
        for(int j = 0; j < 16; j++) asm("imul $1, %%r11" :::"cc", "r11"); // make store slow (taken from example code)
        cause_spec(); // create spec in test 
        __trash = access_test(target_va, 1, __trash, 1); // set up stride change

        _mm_lfence();
        _mm_mfence(); 
        
        __trash = clflush(ptr_under_test, __trash);

        // reset inst state 
        reset_inst();

        _mm_mfence(); 
        _mm_lfence();

        // test 
        __trash = access_test(target_aop, 1, __trash, 1); // test 
        _mm_mfence();

        // sleep 
        __trash = c_sleep(1500, __trash);

        // measure 
        uint64_t test_time = time_access(ptr_under_test, __trash);
        __trash = (__trash | test_time) & MSB_MASK;

        // save
        if(mode == base_mode)
            base[k/2] = test_time; 
        else 
            atk[k/2] = test_time;

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
