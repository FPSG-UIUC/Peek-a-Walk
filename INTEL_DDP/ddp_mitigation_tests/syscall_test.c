#include "../util/util.h"
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <sched.h>
#include <sys/resource.h>
#include <inttypes.h> 

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

    if(argc != 5) {
        fprintf(stderr, "Error Usage: ./fixed.out <training size> <access size> <test ptr offset> <sys_call_case>\n");
        exit(1);
    }

    uint64_t training_size = atoi(argv[1]);
    uint64_t access_size = atoi(argv[2]);          // # of trigger loads in the prefetch phase
    uint64_t test_ptr_offset = atoi(argv[3]);
    uint64_t sys_call_case = atoi(argv[4]);

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

    //Conext swtich setup


    // int a2h[2], h2a[2];        // attacker->hog, hog->attacker
    // pipe(a2h); pipe(h2a);

    // pid_t hog = fork();
    // if (hog == 0) {
    //     pin_cpu(5);
    //     char c;
    //     for (;;) {
    //         read(a2h[0], &c, 1);       // block until attacker pokes -> switch lands on attacker's train->probe
    //         write(h2a[1], &c, 1);      // wake attacker back
    //     }
    // }
    // char c;
    
    sleep(0); 

    /* Main loop */
    uint64_t times[TRIALS] = {0}; 
    uint64_t base_false_positives = 0;   // control trials where ptr_under_test was spuriously cached
    struct rusage r0, r1; getrusage(RUSAGE_SELF, &r0);   // confirm the switch actually happens
    for(int i = 0; i < TRIALS * 2; i++) {
        
        /* Kill the DMP */
        // __trash = access_aop(training_aop, 20, 0, __trash);
        // sleep(0);
        _mm_mfence(); 
        
        /* flush the training aop */
        for(int j = 0; j < training_size; j++) {
            __trash = clflush(training_aop[j], __trash);
            __trash = clflush(training_aop + j, __trash);
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

        switch (sys_call_case) {
            _mm_mfence();
            case 0: 
                _mm_mfence();
                __trash = syscall(SYS_getpid); 
            case 1:
                _mm_mfence();
                __trash = getpid(); 
            case 2: //
                _mm_mfence();
                usleep(0); //kernel level
                break; 
            case 3: //no syscall
                _mm_mfence();
                break;
        }
        _mm_mfence();

        /* activation / prefetch phase: `access_size` trigger loads, each doing a
           SINGLE deref (consumer_load_bit = 0). training above derefs twice
           (consumer_load_bit = 1). mirrors prefetch_distance.c's prefetch loop
           (stride 1). */
        for(uint64_t k = 0; k < access_size; k++) {
            _mm_mfence();
            __trash = access_aop(test_aop + k, 1 /* one load */, 0 /* single deref */, __trash);
        }
        _mm_mfence(); 

        /* give DMP time to catch up */
        __trash = c_sleep(200, __trash);

        /* time access for atck OR ensure no hits in base */ 
        uint64_t trial_access_time = time_access(ptr_under_test, __trash);
        if (i % 2)
            times[i/2] = trial_access_time;
        else if (trial_access_time <= 100)
            base_false_positives++;   // control should miss; count instead of aborting the run

    }
    getrusage(RUSAGE_SELF, &r1);

    // TODO ideally be able to have this directly output to a file
    /* output */ 
    for(int i = 0 ; i < TRIALS; i++)
        fprintf(stderr, "%lu ", times[i]); 
    fprintf(stderr, "\n");
    fprintf(stderr, "BASE_FALSE_POSITIVES: %lu / %d\n", base_false_positives, TRIALS);

    /* verification: case 2 should show vol ~= TRIALS*2 (a switch per trial);
       cases 0/1 should show vol ~= 0. If not, the rung is not doing what its
       label says and any flush result is unattributable. */
    fprintf(stderr, "CTXT_SWITCHES vol=%ld invol=%ld (expect vol~=%d for case 2, ~0 for cases 0/1)\n",
            r1.ru_nvcsw - r0.ru_nvcsw, r1.ru_nivcsw - r0.ru_nivcsw, TRIALS * 2);

    // compute an average 
    uint64_t sum = 0; 
    uint64_t cnt = 0; 
    for(int i = 0 ; i < TRIALS; i++)
        if(times[i] < 100UL) {
            sum += times[i]; 
            cnt++; 
        }
    fprintf(stderr, "Average: %f\n", (sum * 1.0) / (cnt * 1.0));
    printf("trash %" PRIu64 "\n", __trash);

    // kill(hog, SIGKILL);       // stop the spinning child
    // waitpid(hog, NULL, 0); 

    return 0; 
}