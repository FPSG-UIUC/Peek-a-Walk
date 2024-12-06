/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#pragma once

#include <stdint.h>

#include "macros.h"

void solve_lines_threshold_gap(uint64_t *best_past_threshold,
	int64_t *timings, size_t npages, int64_t threshold);
int64_t solve_lines_sorted_all(uint64_t *sorted_lines_by_hits,
	int64_t *timings, size_t npages, int64_t threshold, uint64_t *num_found_lines);