#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "macros.h"
#include "orderOracle.h"

/* General System Information */
// #define ncache_lines 	64 						// number of unqiue cache sets indexes
#define table_size 		4096 					// page table size in bytes
#define line_size 		64 						// cache line size in bytes 
#define pte_size 		8 						// pte size in bytes 
#define pte_per_line 	(line_size / pte_size) 	// pte's per cache line 
// #define trials 			128 					// number of trials 
#define nrounds	 		10 						// measurement rounds 

/* Trial number config macros */
#define NUM_TRIALS_USUAL 128
#define NUM_TRIALS_FAST 16

/* threhsold configs */
#define THRESHOLD_USUAL 55
#define THRESHOLD_FAST 10

/* Functions needed for signal/noise measurements */
typedef uint64_t (* setup_page_walk_trigger_t)(uint64_t, uint64_t, uint64_t);  // address_to_leak, phase (0 = noise, 1 = signal), trash
typedef uint64_t (* trigger_page_walk_t)(uint64_t, uint64_t, uint64_t); // address_to_leak, phase (0 = noise, 1 = signal), trash

/* Return type */
typedef union {
  uint64_t va;
  struct {
    uint8_t po_co:6; 
	uint8_t po_set:6;
	uint8_t vpn1_co:3;
	uint8_t vpn1_set:6;
	uint8_t vpn2_co:3;
	uint8_t vpn2_set:6;
	uint8_t vpn3_co:3;
	uint8_t vpn3_set:6;
	uint8_t vpn4_co:3;
	uint8_t vpn4_set:6;
	uint16_t top:16; // TODO rename to sign bits 
  } __attribute((packed));
} __attribute((packed)) virtual_address_t;

#define EXTRACT_VPN4_BYTE_FROM_VA(va) ((va & (0b111111111L << 39))>>40) 

struct pwsc_ans {
	virtual_address_t va; 
	uint64_t num_lines_found; // TODO change this to num_vpns_found
};

/* Default init evict sizes */
static uint64_t DEFAULT_EVICT_SIZES[MAX_PAGE_LEVELS] = {1920, 32, 2, 2};
static uint64_t MEMORY_MAP_ORDER_ORACLE_EVICT_SIZES[MAX_PAGE_LEVELS] = {4096, 56, 24, 12};
static const uint64_t 
	pagetable_region_sizes[MAX_PAGE_LEVELS]
	= 
	{4 * KIB, 2 * MIB, 1 * GIB, 512 * GIB};  // page table memory region size s

/* Function Predeclarations */
void profile_cache(
	uint64_t target_address, 
	int64_t *timings,
	struct orderOracle *order_oracle,
	uint64_t cur_level);
void apply_noise_filter(int64_t *timings); 
struct pwsc_ans run_pwsc(uint64_t target_address);
uint64_t get_non_buffered_value(uint64_t target_address);

/* Setup/Teardown functions */
void pwsc_init_reset(
	setup_page_walk_trigger_t spwt, 
	setup_page_walk_trigger_t pre_pp, 
	trigger_page_walk_t tpw,
	uint64_t input_init_pwc_sizes[MAX_PAGE_LEVELS],
	int64_t input_solver_gap_threshold,
	uint64_t input_trials);
void pwsc_destroy(void); 

/* noise filter functions */
void reset_noise_filter(void);
