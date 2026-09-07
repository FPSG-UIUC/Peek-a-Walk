#pragma once
#ifndef DMP_SYNC_H
#define DMP_SYNC_H

#include "../util/util.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


#define TRIALS 10000 //2*trials for base and attack
#define SYNC_ROUNDS 2000
#define HIT_THRESHOLD 50
#define TIME_CAP 1000 //drop outliers

#define SHM_NAME "/dmp_threads_exchange"
#define PAGE_SIZE 4096
#define SHM_SIZE (4096 * 2)

//ptr_under_test gets its OWN shm, mapped at a fixed VA in both procs
#define PTR_SHM_NAME "/dmp_test_ptr"
#define PTR_ADDR 0x667000000000UL

typedef struct {
    volatile int count;
    volatile int shared;
} barrier_t;

typedef struct {
    barrier_t barrier;
    volatile int ready;
} control_t;


#define CTRL_ADDY(base) ((control_t*)((char*)(base)))
#define SECRET_ADDY(base) ((volatile uint64_t*)((char*)(base) + PAGE_SIZE)) //one page away from barrier stuff
 
static inline void bar_wait(control_t* ctrl, int* mine) {
    *mine ^= 1; //flip mine
    if (__atomic_add_fetch(&ctrl->barrier.count, 1, __ATOMIC_SEQ_CST) == 2) { //both threads arrived
        //reset barrier
        __atomic_store_n(&ctrl->barrier.count, 0, __ATOMIC_SEQ_CST);
        __atomic_store_n(&ctrl->barrier.shared, *mine, __ATOMIC_SEQ_CST); //now shared == mine -> release other thread
    } else {
        while(*mine != __atomic_load_n(&ctrl->barrier.shared, __ATOMIC_SEQ_CST)) { //spin
            // *mine != (&ctrl->barrier.shared)
            __asm__ volatile ("pause" ::: "memory"); //enforces mem ordering apperantly and cheaper than mm_fence
        }
    }
}

static inline void *shm_create(void){ //victim runs this
    shm_unlink(SHM_NAME);
    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (fd < 0) { perror("shm_open(create)"); exit(1); }
    if (ftruncate(fd, SHM_SIZE) < 0) { perror("ftruncate"); exit(1); }
    void *p = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED)  { perror("mmap(create)"); exit(1); }
    close(fd);
    return p; 
}

static inline void *shm_attach(void) { //timer attaches
    int fd = shm_open(SHM_NAME, O_RDWR, 0666);
    if (fd < 0) { fprintf(stderr, "attach failed, start victim first\n"); exit(1); }
    void *p = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    close(fd);
    return p;
}

static inline void *ptr_create(void) { //victim: make ptr's own shm, map SHARED at fixed VA
    shm_unlink(PTR_SHM_NAME);
    int fd = shm_open(PTR_SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (fd < 0) { perror("shm_open(ptr create)"); exit(1); }
    if (ftruncate(fd, PAGE_SIZE) < 0) { perror("ftruncate(ptr)"); exit(1); }
    void *p = mmap((void*)PTR_ADDR, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    if (p == MAP_FAILED) { perror("mmap(ptr create)"); exit(1); }
    close(fd);
    return p;
}

static inline void *ptr_attach(void) { //timer: attach ptr's shm, map SHARED at same fixed VA
    int fd = shm_open(PTR_SHM_NAME, O_RDWR, 0666);
    if (fd < 0) { fprintf(stderr, "ptr attach failed, start victim first\n"); exit(1); }
    void *p = mmap((void*)PTR_ADDR, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    if (p == MAP_FAILED) { perror("mmap(ptr attach)"); exit(1); }
    close(fd);
    return p;
}


#define TRAIN_BUF_NAME "/dmp_train_buffer"
#define TRAIN_AOP_NAME "/dmp_train_aop"
#define TRAIN_BUF_ADDR 0x666600000000UL
#define TRAIN_AOP_ADDR 0x666700000000UL
#define BUFFER_SIZE (1UL << 20)
#define MAX_TRAINING_SIZE 4096
#define TRAIN_BUF_BYTES (sizeof(uint64_t)  * BUFFER_SIZE * 8)
#define TRAIN_AOP_BYTES (sizeof(uint64_t*) * MAX_TRAINING_SIZE + MB(2))

/* map a named shm at a FIXED VA (create=1 on the owner, 0 on the attacher) */
static inline void *shm_map_fixed(const char *name, void *addr, size_t size, int create) {
    int fd;
    if (create) {
        shm_unlink(name);
        fd = shm_open(name, O_CREAT | O_RDWR, 0666);
        if (fd < 0) { perror("shm_open(map_fixed create)"); exit(1); }
        if (ftruncate(fd, size) < 0) { perror("ftruncate(map_fixed)"); exit(1); }
    } else {
        fd = shm_open(name, O_RDWR, 0666);
        if (fd < 0) { fprintf(stderr, "shm attach failed for %s, start attacker first\n", name); exit(1); }
    }
    void *p = mmap(addr, size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_FIXED | MAP_POPULATE, fd, 0);
    if (p == MAP_FAILED) { perror("mmap(map_fixed)"); exit(1); }
    close(fd);
    return p;
}

#endif