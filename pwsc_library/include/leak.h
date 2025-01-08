#pragma once 

#include "mapping.h"
#include "pwsc.h"

// TODO need to explain the concept of a noise filter 
extern uint64_t noise_filter[ncache_lines];

// TODO port the descriptions to match what the new format 

/*
    leak_pwsc_ptr - leaks a set of 8 byte values in addr
    input: addr, noise filter 
    output: guess_vaddr
*/
struct pwsc_ans leak_pwsc_ptr(uint64_t addr, uint64_t *init_noise_filter);


/*
    leak_addr_range -- leaks bytes in the address range 
    inputs: start_leak, end_leak, page_walk_depth (TODO implement page walk depth feature + shift granularity (1, 2, 4, 8) + ASCII HINT)
    output: a struct bit_map which has byte by byte of the addr range. Note the ends of the range may be imcomplete. NULL if something went wrong 

    Assumption: start_leak > 0 
*/
struct bit_map* leak_addr_range(uint64_t start_leak, uint64_t end_leak, uint64_t gran, uint64_t *init_noise_filter, uint64_t ascii_flag);


/*
 *  leak_userspace_ptr: Leak a secret that appears as an userspace pointer 
 *  Input:      addr of the secret, initial noise config, and expected_vpn4_set (the expected signal vpn4)
 *  Output:     return pwsc_ans with leaked bits
 */
struct pwsc_ans leak_userspace_ptr(uint64_t addr, uint64_t *init_noise_filter, uint64_t expected_vpn4_line);


/*
 * Prints the input bitmap as a string to stderr 
 */
void extract_string(struct bit_map *map); 


/*
    Returns the bit accuracy of the guess and what is correct
    assumptions: bit_map->size = sizeof(correct)
*/
double accuracy(struct bit_map *guess, char *correct);