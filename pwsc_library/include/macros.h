/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#pragma once

#include <limits.h>
#include <stdint.h>
#include <stdio.h>

// #define DEBUG

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

#define KIB ((size_t)1024)
#define MIB (1024 * KIB)
#define GIB (1024 * MIB)

#if SIZE_MAX == UINT64_MAX
#define TIB (1024 * GIB)
#endif

#define MAX_PAGE_LEVELS 4

#define ncache_lines 64