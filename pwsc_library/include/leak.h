#pragma once 

#include "mapping.h"
#include "pwsc.h"

/*
 *  There might sometimes be random cache sets that always have systematic noise that we can't remove. 
 *  E.g. the secret address's PO will make a specific cache set seem touched by the page walk, but it 
 *  is not an important at all and will actually mess with our PWSC (it also isn't removed by our 
 *  differential measurement technique). To combat the noise filter is used to allow `leak.c` to preset
 *  it to mask out that bad cache set signal. 
 */
extern uint64_t noise_filter[ncache_lines];


/*
 *  leak_addr_range --  leaks bytes in the address range [start_leak, end_leak] at byte granularity gran 
 *                      with the inputted initial noise filter config. You can pass an ASCII flag 
 *                      to achieve accuracy and performance improvements if you know the secret is an
 *                      is an ASCII string. 
 *  Inputs: start_leak, end_leak, stride grandularity, init noise filter config, and the ASCII hint
 *  Output: The leaked bits. 
 *  Assumption: start_leak > 0 (or else infinite loop due to integer overflow)
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
 * Returns the bit accuracy of the guess and what is correct
 * Assumptions: bit_map->size = sizeof(correct)
*/
double accuracy(struct bit_map *guess, char *correct);