#pragma once

#ifndef _ALAN_BUNNYHOP
#define _ALAN_BUNNYHOP
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>
#include "../util/util.h"

#define PC_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c%c%c"
#define PC_TO_BINARY(byte)  \
  ((byte) & 0x200 ? '1' : '0'), \
  ((byte) & 0x100 ? '1' : '0'), \
  ((byte) & 0x80 ? '1' : '0'), \
  ((byte) & 0x40 ? '1' : '0'), \
  ((byte) & 0x20 ? '1' : '0'), \
  ((byte) & 0x10 ? '1' : '0'), \
  ((byte) & 0x08 ? '1' : '0'), \
  ((byte) & 0x04 ? '1' : '0'), \
  ((byte) & 0x02 ? '1' : '0'), \
  ((byte) & 0x01 ? '1' : '0') 

/* BH gen item */
#define PC_MASK 0x3ff
#define DEFAULT_BASE 0x666600000000UL
#define DEFAULT_BASE_ADDR_INCREMENT 0x1000000
#define COLLISION_FUNC_START(base, target_addr) (base + ((((uint64_t)target_addr) & PC_MASK) - 13))
#define CONVERT_TO_TRAIN_LOAD_ADDR(addr) (addr - 13)
#define CONVERT_TO_TRIGGER_LOAD_ADDR(addr) (addr - 19)

/* Stide training items */
#define STRIDE_TO_SET (1)
#define STRIDE_TRAINING_LEN (5)
#define SECRET_LOC_IN_TEST_AOP (STRIDE_TO_SET*16)

/* Training items */
#define TRAINING_SIZE (1000+100)

/* DDP eviction items */
#define NUM_DDP_EVICTION_ITEMS 1
#define DDP_EVICTION_AOP_SIZE 32

/* BH init check items */
#define BUNNYHOP_INIT_TRIALS 3

/* BH DDP history reset items */
#define DDP_HISTORY_RESET_LEN 5 

/* BH type defs*/
typedef uint64_t (*bhfunc)(uint64_t *, uint64_t, uint64_t, uint64_t); // aop addr, size, __trash, stride -> returns updated trash 
typedef void (*bhfunc_load)(uint64_t *, uint64_t activate); // target addr

void init_bunnyhop(uint64_t target_pc);

void *create_buffer(uint64_t addr, int size);
void free_buf(void *buffer, uint64_t len); 

bhfunc gen_access_aop(uint64_t addr, int size); 
bhfunc_load gen_test_load(uint64_t addr, uint64_t size);
void free_bh_func(void *addr, int size);
void reset_ddp_hist(bhfunc_load f, uint64_t *garbage); 
void bh_set_stride(bhfunc_load f, uint64_t *aop, uint64_t stride); 

#endif
