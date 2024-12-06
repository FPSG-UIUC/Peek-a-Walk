#include "mapping.h"


/* Shift bit map by one byte */
void shift_one_byte(struct bit_map *to_shift) {
#ifdef DEBUG
    fprintf(stderr, "Size going from %llu to %llu\n", to_shift->cur_pos, to_shift->cur_pos + 1);
#endif
    if((uint64_t)to_shift->cur_pos >= to_shift->size) {
        fprintf(stderr, "Error, shifting past end of the byte map of size %lu\n", to_shift->size); 
        exit(1); 
    }
    to_shift->cur_pos++; 
}

/* Checker function --> ensure previously found + new information match --> returns 1 if it doesn't align properly --> 0 if everything is alright */
// Note: this function ignores the top 16 bits of the 64 bit range 
uint8_t assert_bit_correctness(uint64_t old, uint64_t new, uint64_t page_walk_depth) {

#ifdef DEBUG 
    // meta data
    fprintf(stderr, "Page walk depth: %llu\n", page_walk_depth);

    // output bit mappings to verify     
    fprintf(stderr, "Old:\t\t"); 
    for(int i = 63; i >= 0; i--) {
        fprintf(stderr, "%d", !!((1ULL<<i) & old));
        if(i % 8 == 0) fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "shft:\t\t"); 
    for(int i = 63; i >= 0; i--) {
        fprintf(stderr, "%d", !!((1ULL<<i) & (old << 8)));
        if(i % 8 == 0) fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "New:\t\t"); 
    for(int i = 63; i >= 0; i--) {
        fprintf(stderr, "%d", !!((1ULL<<i) & new));
        if(i % 8 == 0) fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "ign_shft:\t"); 
    for(int i = 63; i >= 0; i--) {
        fprintf(stderr, "%d", !!((1ULL<<i) & ((old << 8) & ignore_mask)));
        if(i % 8 == 0) fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "ign_New:\t"); 
    for(int i = 63; i >= 0; i--) {
        fprintf(stderr, "%d", !!((1ULL<<i) & (new & ignore_mask)));
        if(i % 8 == 0) fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
#endif 

    uint64_t shifted_old = (old << 8) & ignore_mask; // one byte shift 
    uint64_t masked_new = new & ignore_mask; 
    int64_t num_bits_limit = (9 * (page_walk_depth-1)); // one byte shift so last level doesn't exist for the old info 
    for(int64_t cur_bit_idx = 47; cur_bit_idx > 47 - num_bits_limit; cur_bit_idx--) { 
        uint64_t cur_mask = (1ULL)<<cur_bit_idx; 
        // fprintf(stderr, "0x%032llx\n0x%032llx\n\n", (shifted_old & cur_mask), (masked_new & cur_mask));
        if( (shifted_old & cur_mask) != (masked_new & cur_mask) ) return 1; 
    }
    return 0; 
}

/* 
    Add shift + add in new ptr information 
    Assumptions: It has been verified that the new_info is correct --> or else some things will be overwritten
*/ 
void shift_and_add_one_byte(struct bit_map *map, uint64_t new_info) {
    // shift by one byte 
    shift_one_byte(map); 

    // add in new info 
    for(int64_t i = 0; i < 6; i++) { // iterate through all bytes --> not the top 16 bit though
        // uint8_t cur_byte = map->bytes[map->cur_pos + i]; 
        uint8_t new_byte_info = ((((uint64_t)0xff) << (i * 8)) & new_info) >> (i * 8);

        // fill in new information --> use OR 
        map->bytes[map->cur_pos - i] |= new_byte_info;
    }
}

/* Allocate a bit_map */
struct bit_map* create_bit_map(uint64_t num_of_bytes) {
    struct bit_map *ret = malloc(sizeof(struct bit_map)); 
    if(!ret)
        return NULL; 

    ret->bytes = calloc(1, num_of_bytes + 8); // off the end 
    if(!ret->bytes) {
        free(ret);
        return NULL; 
    }

    ret->cur_pos = 0; 
    ret->size = num_of_bytes + 8;
    return ret; 
}

/* destory bit map */
void destroy_bit_map(struct bit_map* to_free) {
    free(to_free->bytes);
    free(to_free); 
}

/* Helper function to extract out the current ptr (uint64_t) recorded */
uint64_t get_cur_ptr(struct bit_map *cur) {
    if(cur->cur_pos < 7) return 0; // has to have at least one ptr 

    uint64_t ret = 0;
    for(int i = 0; i < 8; i++) 
        ret |= (((uint64_t)cur->bytes[cur->cur_pos - i]) << (i * 8)); 
    return ret; 
}

void write_ptr_to_map(struct bit_map *map, uint64_t ptr) {
    for(int64_t i = 0; i < 8; i++) { // iterate through all bytes --> 
        uint8_t cur_byte = ((((uint64_t)0xff) << (i * 8)) & ptr) >> (i * 8);
        map->bytes[map->cur_pos - i] = cur_byte;
    }
}

void set_start_to_ptr(struct bit_map *map, uint64_t ptr) {
    map->cur_pos = 7;
    write_ptr_to_map(map, ptr);
}

/* 
    add_ptr_to_bit_map - maps bits found into an array  
    inputs: bit_map, uint64_t new_info, uint64_t page_walk_depth, and do_check (assertion check?)
    output: 0 if everything went well and stuff added, 1 if assertion checks failed and there is a mismatch 
*/
uint8_t add_ptr_to_bit_map(struct bit_map *map, uint64_t new_info, uint64_t page_walk_depth, uint64_t do_check) {
    uint64_t old_info = 0; 
    if(map->cur_pos != 0 && do_check) old_info = get_cur_ptr(map); 

    // assertion check -- must match previous data 
    if(do_check && assert_bit_correctness(old_info, new_info, page_walk_depth))
        fprintf(stderr, "[WARNING] assertion of bit correctness failed!\n");

    // add in new information (one extra byte)
    if(map->cur_pos == 0) set_start_to_ptr(map, new_info);
    else shift_and_add_one_byte(map, new_info); 

    return 0; 
}
