#include <stdint.h>
#include <stdlib.h>

#include "macros.h"
#include "solver.h"

/* Gets all the lines that are past the treshold with the prime probe strategy */
/* Returns the singular line that is the max by a gap, if no such pointer exists it returns ncache_lines (out of bounds)*/
void solve_lines_threshold_gap(uint64_t *best_past_threshold,
	int64_t *timings, size_t npages, int64_t threshold)
{
	/* solve all possibilities using solve_line and pick the best one
	 * and store it in best_line and best_page.
	 */
	int64_t best_line_sum = -1 * threshold;
	uint64_t best_line = ncache_lines;
	int met_threshold = 1; 
	size_t page; 

	for (size_t line = 0; line < ncache_lines; ++line) { 
		int64_t line_sum = 0; 
		for (page = 0; page < npages; ++page) { 
			line_sum += timings[page * ncache_lines + line];
		}
		if(line_sum > best_line_sum) {
			if(line_sum >= best_line_sum + threshold) met_threshold = 1; 
			else met_threshold = 0; 

			best_line_sum = line_sum; 
			best_line = line;  
		}
		else if(line_sum + threshold > best_line_sum) met_threshold = 0; 
	}

	if(met_threshold) {
		*best_past_threshold = best_line;
	} else {
		*best_past_threshold = ncache_lines;
	}
}

/* Returns a sorted list of all the best lines */
/* Returns the diff */
int64_t solve_lines_sorted_all(uint64_t *sorted_lines_by_hits,
	int64_t *timings, size_t npages, int64_t threshold, uint64_t *num_found_lines)
{
	/* solve all possibilities using solve_line and pick the best one
	 * and store it in best_line and best_page.
	 */
	int64_t lines_sum[ncache_lines];  

	for (size_t line = 0; line < ncache_lines; ++line) { 
		int64_t line_sum = 0; 
		for (size_t page = 0; page < npages; ++page) { 
			line_sum += timings[page * ncache_lines + line];
		}
		lines_sum[line] = line_sum;
	}

	// simple selection sort since ncache_lines == 64 
	int64_t diff = 0; 
	int v[ncache_lines]; 
	for(uint64_t i = 0; i < ncache_lines; i++) v[i] = 0; 
	for(uint64_t i = 0; i < ncache_lines; i++) {
		int64_t best_sum = -100; 
		uint64_t best_line = ncache_lines;
		for(uint64_t j = 0; j < ncache_lines; j++) {
			if(v[j]) continue; 
			if(lines_sum[j] >= best_sum) {
				best_sum = lines_sum[j]; 
				best_line = j; 
			}
		}
		v[best_line] = 1; 
		sorted_lines_by_hits[i] = best_line;
		if(i == 0) diff += best_sum;
		else if(i == 1) diff -= best_sum;
	}

	// Calculate diff drop off (for the printout)
	*num_found_lines = 0; 
	for(uint64_t i = 0; i < 7; i++) {
		if(lines_sum[sorted_lines_by_hits[i]] >= threshold) {
			*num_found_lines = i + 1; 
		}
	}

	fprintf(stdout, "Diff %ld\tLines found: %lu\n", diff, *num_found_lines); 
	return diff;
}
