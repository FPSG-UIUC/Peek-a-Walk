#include "../util/util.h"
#include "../bunnyhop/bunnyhop.h"
#include <sys/mman.h>
#include <pthread.h> 
#include <semaphore.h> 
#include <signal.h>

#define SNAME_PARENT "alan_sema_parent_test"
#define SNAME_CHILD "alan_sema_child_test"

// TODO urd00m: make these a command line argument
#define IDX_TO_CHECK 16
#define CROSS_PROCESS 0

uint64_t core_id;
uint64_t repititions; 
uint64_t training_size; 
uint64_t sort_output;

uint64_t (* access_aop)(uint64_t*, uint64_t, uint64_t, uint64_t);

// thread 
void * child_process_work(uint64_t *buf) {
    uint64_t __trash = 0; 

    // init 
    uint64_t *secret = buf[IDX_TO_CHECK]; 
    *secret = rand(); 
    __trash = clflush(secret, __trash); 

    // pin 
    pin_cpu(core_id);
    sem_t *sem_parent = sem_open(SNAME_PARENT, 0); /* Open a preexisting semaphore. */
    sem_t *sem_child = sem_open(SNAME_CHILD, 0); /* Open a preexisting semaphore. */

    // begin loop 
    while(1) {
        sem_wait(sem_child);         
        asm("mov (%0), %%rax\n"
            "mfence\n"
            : 
            : "r" (buf)
            : "cc", "rax"); 

        // Timing 
        __trash = c_sleep(1500, __trash); 
        uint64_t test_time = time_access(secret, __trash);
        __trash = (__trash | test_time) & MSB_MASK;
        _mm_mfence();
        __trash = clflush(secret, __trash); 
        _mm_mfence();
        fprintf(stderr, "%lu ", test_time);
        sem_post(sem_parent); 
    }
    return NULL;
}

int main(int argc, char **argv) {

    // arg parse
    if(argc != 5) {
        printf("Usage: ./process.out <core id> <repititions> <training size> <sort output?>\n");
        exit(1);
    }
    core_id = atoi(argv[1]);
    repititions = atoi(argv[2]);
    training_size = atoi(argv[3]);
    sort_output = atoi(argv[4]);

    printf("Experiment Setup:\n");
    printf("Core id: \t\t\t\t%lu\n", core_id);
    printf("repititions: \t\t\t\t%lu\n", repititions);
    printf("Training Size: \t\t\t\t%lu\n", training_size);
    printf("sort output: \t\t\t\t%lu\n", sort_output);
    printf("Cross process: \t\t\t\t%d\n", CROSS_PROCESS);

    // pin to pcore 
    pin_cpu(core_id); 

    // open the semaphores 
    sem_t *sem_parent = sem_open(SNAME_PARENT, O_CREAT, 0644, 0); /* Initial value is 3. */
    sem_t *sem_child = sem_open(SNAME_CHILD, O_CREAT, 0644, 0); /* Initial value is 3. */

    // setup aop buffer streams 
    uint64_t test_ptr_after = 0; // legacy support sometime in future please remove this lol 
    SETUP_AOP(training_aop);
    SETUP_DATA_BUFFER(training_data_buffer);

    // set up target buffers 
    srand(10);
    if(training_size > 0) {
        for(int i = 0; i < training_size; i++) 
            training_aop[i] = (uint64_t)&training_data_buffer[(rand() & (DATA_BUFFER_MASK - 1)) * U64S_PER_CACHE_LINE];
    } else {
        printf("Error, 0 training pointers makes no sense ...\n");
        return -1; 
    }

    // secrets what we want to leak 
    uint64_t *buf = malloc(30 * sizeof(uint64_t)); 
    uint64_t *secret = malloc(sizeof(uint64_t)); 
    *secret = (rand() & (MSB_MASK - 1)) ; 
    for(int i = 1; i < 30; i++) buf[i] = secret; 

    // trash
    uint64_t __trash = 0; 

    // thrash ddp state 
    sleep(0); 

    // start up child process 
#if CROSS_PROCESS 
    pid_t pid = fork(); 
    if(pid == 0) { // we are child 
        child_process_work(buf); 
        return 0; // exit 
    }
#else
    pthread_t pid;
    int status = pthread_create(&pid, NULL, child_process_work, buf);
    if(status != 0) {
        printf("thread start failure!\n");
        exit(1);
    }
#endif 

    // generate training function with PC alias 
    access_aop = gen_access_aop(COLLISION_FUNC_START(DEFAULT_BASE, ((uint64_t)child_process_work) + 0x68), training_size);
    _mm_mfence();

    fprintf(stderr, "Atck: ");
    for(int k = 0; k < repititions; k++) {

        _mm_mfence(); 
        _mm_lfence();

        // training 
        _mm_mfence();
        __trash = access_aop(training_aop, training_size, __trash, 1);

        _mm_mfence(); 
        _mm_lfence();

        // switch to victim  
        sem_post(sem_child); 
        sem_wait(sem_parent);
    }
    fprintf(stderr, "\n");

    // clear state 
    sleep(0); 

    fprintf(stderr, "Base: ");
    for(int k = 0; k < repititions; k++) {

        _mm_mfence(); 
        _mm_lfence();

        // training 
        _mm_mfence();

        _mm_mfence(); 
        _mm_lfence();

        // switch to victim  
        sem_post(sem_child); 
        sem_wait(sem_parent);
    }
    fprintf(stderr, "\n");

    // TODO urd00m: better way of doing this clean up lol 
    kill(pid, SIGKILL);
    sem_destroy(sem_child);
    sem_destroy(sem_parent);
}
