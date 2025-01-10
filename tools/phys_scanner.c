#include <fcntl.h>
#include <stdlib.h> 
#include <stdint.h> 
#include <stdio.h> 
#include <errno.h>
#include <unistd.h> 

#define BIN_DATA_SIZE 512UL * 1024 * 1024 // 512 MB

/*
 *  This tool takes in a binary data dump of physmap (any size) and processes it to generate the
 *  the stats in Table 1 of our Peek-a-Walk paper. 
 * 
 *  It might seem confusing at first, but all it is doing is keep a running bitmask of the 
 *  already leaked bits. Thus when new bits are learned we don't double count. In the end
 *  this will print out all the possible leak bit stats.
 */

uint64_t extract_u64(uint8_t *data) {
    uint64_t ret = 0;
    for (uint64_t i = 0; i < 8; i++) {
        ret |= ((uint64_t)((uint8_t)data[i])) << (i * 8);
    }
    return ret;
}

uint64_t lam_canonical(uint8_t *data, uint64_t userspace_only) {
    if (((uint8_t)data[7] & 0b10000000) == ((uint8_t)data[5] & 0b10000000)) {
        if (userspace_only) {
            if (((uint8_t)data[7] & 0b10000000) == 0) {
                return 1;
            } else {
                return 0;
            }
        } else {
            return 1;
        }
    } else {
        return 0;
    }
}

uint64_t canonical(uint8_t *data) {
    if (data[7] != data[6]) {
        return 0;
    }
    if (data[7] != 0 && data[7] != 255) {
        return 0;
    }
    if (data[7] == 0 && ((data[5] & 0b10000000) != 0)) {
        return 0;
    }
    if (data[7] == 255 && ((data[5] & 0b10000000) != 128)) {
        return 0;
    }
    return 1;
}

uint64_t learned_mask_lam(uint8_t *data, uint64_t userspace_only) {
    if (!lam_canonical(data, userspace_only)) {
        return 0;
    }
    if (data[7] == 255) {
        return 0b1000000000000000111111000000000000000000000000000000000000000000UL;
    } else {
        return 0b1000000000000000111111111111111111111111111111111111000000000000UL;
    }
}

uint64_t learned_mask(uint8_t *data) {
    if (!canonical(data)) {
        return 0;
    }
    if (data[7] == 255) {
        return 0b1111111111111111111111000000000000000000000000000000000000000000UL;
    } else {
        return 0b1111111111111111111111111111111111111111111111111111000000000000UL;
    }
}

uint64_t new_bits(uint64_t o, uint64_t n) {
    uint64_t new_bits = 0;
    uint64_t mask = 1UL;
    for (uint64_t i = 0; i < 64; i++) {
        if (((n & mask) > 0) && ((o & mask) == 0))
            new_bits += 1;
        mask <<= 1;
    }
    return new_bits;
}

/* Count top byte at a time */
uint64_t learned_interesting(uint64_t mask) {
    return new_bits(0b1111111111111111111111111111111111111111111111111111111100000000UL, mask);
}

uint64_t new_bits_nonzero(uint64_t o, uint64_t n, uint64_t val) {
    uint64_t new_bits = 0;
    uint64_t mask = 1UL;
    for (uint64_t i = 0; i < 64; i++) {
        if (((n & mask) > 0) && ((o & mask) == 0) && (val & mask))
            new_bits += 1;
        mask <<= 1;
    }
    return new_bits;
}

int main(int argc, char **argv) {
    fprintf(stderr, "Running\n");
    fprintf(stderr, "%d\n", argc);

    asm volatile("");
    
    if (argc != 2) {
        fprintf(stderr, "Usage: ./program <file_name>\n");
        return 1;
    } else {
        char *file_name = argv[1];

        FILE *file = fopen(file_name, "rb");
        if (file == NULL) {
            printf("File not found: %s\n", file_name);
            return 1;
        }

        uint64_t total_mem_size = 1024UL * 1024 * 1024 * 16 * 8; // bits in memory
        uint64_t total_leakage_lam = 0;
        uint64_t total_leakage_lam_userspace = 0;
        uint64_t total_leakage_reg = 0;
        uint64_t total_leakage_lam_interesting = 0;
        uint64_t total_leakage_reg_interesting = 0;
        uint64_t total_leakage_lam_userspace_interesting = 0;
        uint64_t num_zero_bits_seen = 0; 
        uint64_t total_bits_seen = 1; 

        while (!feof(file)) {
            uint8_t *binary_data = malloc(BIN_DATA_SIZE);
            uint64_t bytes_read = fread(binary_data, 1, BIN_DATA_SIZE, file);

            uint64_t old_mask_lam = 0;
            uint64_t old_mask_lam_userspace = 0;
            uint64_t old_mask = 0;

            for (uint64_t i = 0; i < bytes_read - 10; i++) {
                if (i % (2 * 1024 * 1024) == 0) {
                    printf("Progress %lu/%lu\t%.2f%%\n", total_bits_seen, total_mem_size / 8, ((float)(total_bits_seen) / (total_mem_size)) * 100);
                    printf("Bits in memory: %lu\tZero bits: %lu\n", total_mem_size, num_zero_bits_seen);
                    printf("total leakage\t\t\tLAM: %lu\t%.2f%%\tno LAM: %lu\t%.2f%%\tuser lam only: %lu\t%.2f%%\n", total_leakage_lam, ((float)(100 * total_leakage_lam) / (total_bits_seen)), total_leakage_reg, ((float)(100 * total_leakage_reg) / (total_bits_seen)), total_leakage_lam_userspace, ((float)(100 * total_leakage_lam_userspace) / (total_bits_seen)));
                    printf("total leakage interesting\tLAM: %lu\t%.2f%%\tno LAM: %lu\t%.2f%%\tuser lam only: %lu\t%.2f%%\n", total_leakage_lam_interesting, ((float)(100 * total_leakage_lam_interesting) / (total_bits_seen - (num_zero_bits_seen))), total_leakage_reg_interesting, ((float)(100 * total_leakage_reg_interesting) / (total_bits_seen - (num_zero_bits_seen))), total_leakage_lam_userspace_interesting, ((float)(100 * total_leakage_lam_userspace_interesting) / (total_bits_seen - (num_zero_bits_seen))));
                    printf("\n");
                }

                uint64_t cur_mask_lam = 0;
                uint64_t cur_mask = 0;
                uint64_t cur_mask_lam_userspace = 0;

                uint8_t *data = binary_data + i;

                cur_mask_lam = learned_mask_lam(data, 0);
                cur_mask = learned_mask(data);
                cur_mask_lam_userspace = learned_mask_lam(data, 1);

                uint64_t learned_bits_lam = new_bits(old_mask_lam, cur_mask_lam);
                uint64_t learned_bits = new_bits(old_mask, cur_mask);
                uint64_t learned_bits_lam_userspace = new_bits(old_mask_lam_userspace, cur_mask_lam_userspace);
                total_leakage_lam += learned_bits_lam;
                total_leakage_reg += learned_bits;
                total_leakage_lam_userspace += learned_bits_lam_userspace;

                // Only count upper byte for now 
                if(data[0] != 0) {
                    total_leakage_lam_interesting += learned_interesting(old_mask_lam);
                    total_leakage_reg_interesting += learned_interesting(old_mask);
                    total_leakage_lam_userspace_interesting += learned_interesting(old_mask_lam_userspace);
                }
                if(data[0] == 0) num_zero_bits_seen += 8;
                total_bits_seen += 8;

                // Update old masks
                old_mask_lam = ((old_mask_lam | cur_mask_lam) >> 8);
                old_mask = ((old_mask | cur_mask) >> 8);
                old_mask_lam_userspace = ((old_mask_lam_userspace | cur_mask_lam_userspace) >> 8);
            }

            free(binary_data);
        }

        fclose(file);
    }

    return 0;
}