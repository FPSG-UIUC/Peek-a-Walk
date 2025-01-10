#include <stdio.h>
#include <stdint.h> 
#include <string.h> 
#include <stdlib.h> 
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>


static uint64_t virt_to_physmap(uint64_t virtual_address) {
    int pagemap;
    uint64_t value;
    int got;
    uint64_t page_frame_number;
    uint64_t page_offset = 0xffff888000000000UL; 

    pagemap = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap < 0) {
        exit(1);
    }

    got = pread(pagemap, &value, 8, (virtual_address / 0x1000) * 8);
    if (got != 8) {
        exit(2);
    }

    page_frame_number = value & ((1ULL << 54) - 1);
    if (page_frame_number == 0) {
        exit(3);
    }

    close(pagemap);

    return page_offset + (page_frame_number * 0x1000 + virtual_address % 0x1000);
}

int main(void) {
    char *secret_ascii = "After the discovery of Data Memory Prefetchers (DMP) in the wild, we have started to see initial studies into the security implications of these structures [2, 7]. However, past work has only explored the Apple DMP and only offered surface level intuition on other platforms like Intel. In this section we present a comprehensive investigation of Intels new Data Dependent Prefetcher(DDP) on Intels Raptor Lake architecture (13th and 14th genera-tion). We show that while it is the same class of prefetcher as the Apple DMP, Intels DDP could not be more different and comes with a completely different set of challenges. Figure 1 shows the high level differences between the Apple DMP and our findingsfor the Intel DDP. To guide our investigation and demonstrate the various challenges Intels DDP brings we answer the following four questions\n"; 
    char *secret_ascii2 = calloc(1, 1024); 
    strcpy(secret_ascii2, "From our previous experiments we have already found that Intels DDP behaves differently from the Apple DMP. Specifically, the DDP does not appear to be stateless and requires a training period. This is already different from what exists in the literature as the Apple DMP does not require a training period. We therefore intend to get a better understanding of the inner workings of Intels DDP starting by gaining a better understanding of the DDPs training patterns. The ability to train the DDP properly is a critical first step for any attack and needed to better understand the DDPs structure. To fill the gap surrounding the training period, we identify and discuss three DDP training mechanics.");

    fprintf(stderr, "Secret is: <%s>\n", secret_ascii); 
    fprintf(stderr, "Secret2 is: <%s>\n", secret_ascii2); 
    fprintf(stderr, "Phys map location: 0x%lxUL\n", virt_to_physmap((uint64_t)secret_ascii)); 
    fprintf(stderr, "Phys map location2: 0x%lxUL\n", virt_to_physmap((uint64_t)secret_ascii2)); 

    while (1) {};
    return 0; 
}