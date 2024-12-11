#include "pwsc.h"
#include "mapping.h"
#include "util.h"
#include <time.h>

uint64_t setup_trigger(uint64_t target, uint64_t phase, uint64_t __trash) {
    (void) phase;
    *(uint64_t *)target = 0x5A; 
    return __trash; 
}

uint64_t trigger(uint64_t target, uint64_t phase, uint64_t __trash) {
    if(phase) *(uint64_t *)target = 0x5A; 
    return __trash; 
}

int main(void) {
    // pin cpu 
    pin_cpu(0);
    srand(time(0)); 

    // Experiment setup
    fprintf(stderr, "Running simple test\n");  
    fprintf(stderr, "Using the PWC order oracle\n");
    fprintf(stderr, "Architectural derefence\n");  
    fprintf(stderr, "Fast configurations\n");    
    pwsc_init_reset(setup_trigger, NULL, trigger, DEFAULT_EVICT_SIZES, THRESHOLD_FAST, NUM_TRIALS_FAST); 

    // setup target 
    uint64_t *target = mmap(NULL, 4096 * 10, 
                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
			    -1, 0 );
    target += (rand() % 4096); 
    *target = 0x5A; 

    // start 
    fprintf(stderr, "Target Secret Value: 0x%lx\tTarget's VPNs + PO are %lu %lu %lu %lu %lu\n", 
			(uint64_t) target,
			VPN4_TO_CACHE_LINE(target), 
			VPN3_TO_CACHE_LINE(target), 
			VPN2_TO_CACHE_LINE(target), 
			VPN1_TO_CACHE_LINE(target), 
			PO_TO_CACHE_LINE(target));
    fprintf(stderr, "\n\n\n");

    // Run the PWSC
    struct pwsc_ans ans = run_pwsc((uint64_t)target);  

    // Stats
    int correct_bits = bit_accuracy_checker(ans.va.va, (uint64_t)target); 
    fprintf(stderr, "\nRecovered Secret value: 0x%lx\tCorrect bits: %d\tImprovement Over Random: %d\n", ans.va.va, correct_bits, correct_bits - 32);
}
