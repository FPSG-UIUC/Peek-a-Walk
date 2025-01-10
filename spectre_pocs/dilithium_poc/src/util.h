#ifndef __UTIL_H__
#define __UTIL_H__
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

#include "params.h"

#define PAGE_SIZE 4096
#define MLEN 59
#define PHYSMAP_START  (0xffff888000000000)

#define MEM_BARRIER  asm volatile("mfence")
// #define INST_BARRIER asm volatile("cpuid")
#define INST_BARRIER asm volatile ("xor %%rax, %%rax\ncpuid\n\t" ::: "%rax", "%rbx", "%rcx", "%rdx")

// static __always_inline __attribute__((always_inline)) void cpuid(void) {
//     asm volatile ("xor %%rax, %%rax\ncpuid\n\t" ::: "%rax", "%rbx", "%rcx", "%rdx");
// }

typedef struct
{
    uint64_t msg_flag;
    uint8_t msg[MLEN + CRYPTO_BYTES];
} msg_t;


// file id for pagemap lookup
int pg_fd = -1;
static void load_pagemap(int pid) {
    char filename[BUFSIZ];
    snprintf(filename, sizeof filename, "/proc/%d/pagemap", pid);

    pg_fd = open(filename, O_RDONLY);
    if(pg_fd < 0) {
        perror("load pagemap");
        exit(1);
    }
}

static uint64_t get_pfn(uint64_t addr_utest) {
    uint64_t buf;
    uint64_t offset = (addr_utest / PAGE_SIZE) * sizeof(buf);

    if(pread(pg_fd, &buf, sizeof(buf), offset) != sizeof(buf)) {
        perror("pread");
        exit(1);
    }
    return buf & 0x7fffffffffffff;
}

static uint64_t* create_shared_memory(const char* path)
{
    printf("%s\n", path);
    int fd = open(path, O_RDWR, 0644);
    if (fd == -1) {
        fprintf(stderr, "[-] Error opening file\n");
        exit(1);
    }

    return (uint64_t*)mmap(NULL, sizeof(msg_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0);
}

static uint64_t u64_leak(uint64_t addr) {
    int kernel_fd = -1; 
    uint64_t data = 0; 
    for(int i = 0; i < 8; i++) {  
        uint64_t cur_addr = addr + i; 
        uint64_t cur_byte = 0;   
        kernel_fd = open("/proc/mem_scanner_tool/scan_mem", O_WRONLY); 
        write(kernel_fd, &cur_addr, sizeof(uint64_t));
        close(kernel_fd);
        kernel_fd = open("/proc/mem_scanner_tool/scan_mem", O_RDONLY);
        read(kernel_fd, &cur_byte, 8);
        close(kernel_fd);

        data |= (cur_byte << (i*8)); 
    }
    return data; 
}

#endif
