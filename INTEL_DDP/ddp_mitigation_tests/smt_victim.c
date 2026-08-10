#include "../util/util.h"
#include <sys/mman.h>
#include "dmp_shared.h"

#define PAGESIZE (4096)
#define CORE_PROBE 6  

/* same gadget as the attacker; here it's driven single-deref to TRIGGER the DMP */
__attribute__((aligned(1024), noinline))
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
        "or (%%rax), %0\n"

        "2:\n"
        "add $1, %%r12\n"
        "add $1, %%r13\n"
        "cmp %3, %%r13\n"

        "jl 1b\n"
        : "=r" (__trash)
        : "r" (aop), "0" (__trash), "r" (size), "r" (consumer_load_bit)
        : "cc", "r11", "r12", "r13", "rax", "rbx"
    );
    return __trash & MSB_MASK;
}

int main(int argc, char **argv) {

    if(argc != 3) {
        fprintf(stderr, "Error Usage: ./victim.out <access size> <test ptr offset>\n");
        exit(1);
    }
    uint64_t access_size     = atoi(argv[1]);   // # of single-deref trigger loads on test_aop
    uint64_t test_ptr_offset = atoi(argv[2]);
    test_ptr_offset++;                          // triggering access starts at index 0

    /* attach the attacker's control/barrier region (sync only) */
    void *base = shm_attach();
    control_t *c = CTRL_ADDY(base);

    while(!__atomic_load_n(&c->ready, __ATOMIC_SEQ_CST))   // wait for the attacker to set up
        asm volatile("pause" ::: "memory");

    uint64_t __trash = 0;
    pin_cpu(CORE_PROBE);
    _mm_mfence();

    shm_map_fixed(TRAIN_BUF_NAME, (void*)TRAIN_BUF_ADDR, TRAIN_BUF_BYTES, 0);
    shm_map_fixed(TRAIN_AOP_NAME, (void*)TRAIN_AOP_ADDR, TRAIN_AOP_BYTES, 0);

    /* test aop: PRIVATE to the victim, at fixed VAs */
    uint64_t buffer_size = BUFFER_SIZE;
    uint64_t test_size   = 100;
    uint64_t *test_buffer = (uint64_t *) mmap ( (void*)(0x666800000000UL), sizeof(uint64_t) * buffer_size * 8,
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE, -1, 0 );
    for(uint64_t i = 0; i < buffer_size * 8; i+=8)
        test_buffer[i] = rand();
    uint64_t **test_aop = (uint64_t **) mmap ( (void*)(0x666900000000UL), sizeof(uint64_t *) * test_size + MB(2),
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE, -1, 0 );
    assert((uint64_t)test_aop % MB(2) == 0); // align to 2 MB
    for(int i = 0; i < test_size; i++)
        test_aop[i] = &test_buffer[(rand() % buffer_size) * 8];

    /* keep ptr_under_test far from test_aop */
    volatile uint64_t *guard_page = malloc(MB(2) * sizeof(uint64_t));
    for(int i = 0; i < MB(2); i += 4096)
        guard_page[i] = rand();

    /* ptr_under_test: PRIVATE to the victim, at a fixed VA */
    // volatile uint64_t *ptr_under_test = (uint64_t *) mmap ( (void*)(0x667000000000UL), 4096,
	// 		     PROT_READ | PROT_WRITE,
	// 		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE, -1, 0 );
    volatile uint64_t *ptr_under_test = ptr_attach(); //own shm, shared + fixed VA
    assert((uint64_t)ptr_under_test % 64 == 0); // cache-line aligned
    *ptr_under_test = 0xdeadbeef;
    //test_aop[test_ptr_offset] = ptr_under_test;

    /* Phase 1: barrier smoke-test  */
    { int mine = 0;
        for(int k = 0; k < SYNC_ROUNDS; k++) {
            bar_wait(c, &mine);
            bar_wait(c, &mine);
        }
        fprintf(stderr, "[sync] barrier handshake ok (%d rounds)\n", SYNC_ROUNDS);
    }

    uint64_t times[TRIALS] = {0};
    uint64_t base_hits = 0;
    { int mine = 0;
      for(int i = 0; i < TRIALS * 2; i++) {


          /* base vs probe */
          if( i % 2 )
              test_aop[test_ptr_offset] = ptr_under_test;
          else
              test_aop[test_ptr_offset] = NULL;

          /* flush ptr so a hit can only come from a prefetch during this trigger */
          __trash = clflush(ptr_under_test, __trash);
          _mm_mfence();

          bar_wait(c, &mine);  //let attacker train
          bar_wait(c, &mine); //attacker finished training

          /* activation */
          for(uint64_t k = 0; k < access_size; k++) {
              _mm_mfence();
              __trash = access_aop(test_aop + k, 1 /* one load */, 0 /* single deref */, __trash);
          }
          _mm_mfence();

          /* let the DMP catch up */
          __trash = c_sleep(200, __trash);

          /* detect on the victim's own private line */
          uint64_t t = time_access(ptr_under_test, __trash);

          bar_wait(c, &mine);   // release attacker for next trial

          if(i % 2) times[i/2] = t;
          else if(t < HIT_THRESHOLD) base_hits++;
      }
    }

    /* results */
    uint64_t sum = 0, cnt = 0, hits = 0;
    for(int i = 0; i < TRIALS; i++) {
        if(times[i] < HIT_THRESHOLD) hits++;
        if(times[i] < TIME_CAP) { sum += times[i]; cnt++; }
    }
    fprintf(stderr, "[dmp] attack: mean %.1f cyc, hit-rate %.1f%% (%lu/%d)\n",
            cnt ? (double)sum/cnt : 0.0, 100.0*hits/TRIALS, hits, TRIALS);
    fprintf(stderr, "[dmp] base:   hit-rate %.1f%% (%lu/%d)  <- near 0 if clean\n",
            100.0*base_hits/TRIALS, base_hits, TRIALS);
    fprintf(stderr, "[dmp] within-run: prefetch is chasing the OOB pointer iff attack >> base.\n");
    fprintf(stderr, "[dmp] cross-thread transfer: also rerun with the ATTACKER idle; real iff hit-rate(attacker training) >> hit-rate(attacker idle).\n");

    /* raw attack samples for your plotting tooling (same format as exist.c) */
    for(int i = 0; i < TRIALS; i++)
        fprintf(stderr, "%lu ", times[i]);
    fprintf(stderr, "\n");

    //shm_unlink(PTR_SHM_NAME);
    return 0;
}