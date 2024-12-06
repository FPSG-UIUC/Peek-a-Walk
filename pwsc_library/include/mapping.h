/*
    Author: Alan Wang <alanlw2@illinois.edu> 

    In progress - DO NOT DISTRIBUTE 

    hehe 
*/

#pragma once

#include "macros.h"
#include "pwsc.h"

// TODO comments! 

#define VPN4_BITMASK    (0b111111111L << 39)
#define VPN3_BITMASK    (0b111111111L << 30)
#define VPN2_BITMASK    (0b111111111L << 21)
#define VPN1_BITMASK    (0b111111111L << 12)
#define PO_BITMASK      (0b111111111111L)

#define ZERO_SIGN_EXT(va) (((uint64_t)va) & (~TOP_MASK))
#define ZERO_VPN4(va)   (((uint64_t)va) & (~VPN4_BITMASK))
#define ZERO_VPN3(va)   (((uint64_t)va) & (~VPN3_BITMASK))
#define ZERO_VPN2(va)   (((uint64_t)va) & (~VPN2_BITMASK))
#define ZERO_VPN1(va)   (((uint64_t)va) & (~VPN1_BITMASK))
#define ZERO_PO(va)     (((uint64_t)va) & (~PO_BITMASK))

#define VPN4_TO_CACHE_LINE(va) (((uint64_t)va & VPN4_BITMASK) >> 42)
#define VPN3_TO_CACHE_LINE(va) (((uint64_t)va & VPN3_BITMASK) >> 33)
#define VPN2_TO_CACHE_LINE(va) (((uint64_t)va & VPN2_BITMASK) >> 24)
#define VPN1_TO_CACHE_LINE(va) (((uint64_t)va & VPN1_BITMASK) >> 15)
#define PO_TO_CACHE_LINE(va)   (((uint64_t)va & PO_BITMASK) >> 6)

#define VA_VPN4_TO_VPN(va) (((uint64_t)va & VPN4_BITMASK) >> 39)
#define VA_VPN3_TO_VPN(va) (((uint64_t)va & VPN3_BITMASK) >> 30)
#define VA_VPN2_TO_VPN(va) (((uint64_t)va & VPN2_BITMASK) >> 21)
#define VA_VPN1_TO_VPN(va) (((uint64_t)va & VPN1_BITMASK) >> 12)

#define CACHE_LINE_TO_VPN4(line)    (((uint64_t)line) << 42)
#define CACHE_LINE_TO_VPN3(line)    (((uint64_t)line) << 33)
#define CACHE_LINE_TO_VPN2(line)    (((uint64_t)line) << 24)
#define CACHE_LINE_TO_VPN1(line)    (((uint64_t)line) << 15)
#define CACHE_LINE_TO_PO(line)      (((uint64_t)line) << 6)

#define SET_VA_VPN4_TO_LINE(va, line) (ZERO_VPN4(va) | CACHE_LINE_TO_VPN4(line))
#define SET_VA_VPN3_TO_LINE(va, line) (ZERO_VPN3(va) | CACHE_LINE_TO_VPN3(line))
#define SET_VA_VPN2_TO_LINE(va, line) (ZERO_VPN2(va) | CACHE_LINE_TO_VPN2(line))
#define SET_VA_VPN1_TO_LINE(va, line) (ZERO_VPN1(va) | CACHE_LINE_TO_VPN1(line))
#define SET_VA_PO_TO_LINE(va, line)   (ZERO_PO(va) | CACHE_LINE_TO_PO(line))

#define VPN_TO_VPN4(vpn)    (((uint64_t)vpn) << 39)
#define VPN_TO_VPN3(vpn)    (((uint64_t)vpn) << 30)
#define VPN_TO_VPN2(vpn)    (((uint64_t)vpn) << 21)
#define VPN_TO_VPN1(vpn)    (((uint64_t)vpn) << 12)

#define SET_VA_VPN4_TO_VPN(va, vpn) (ZERO_VPN4(va) | VPN_TO_VPN4(vpn))
#define SET_VA_VPN3_TO_VPN(va, vpn) (ZERO_VPN3(va) | VPN_TO_VPN3(vpn))
#define SET_VA_VPN2_TO_VPN(va, vpn) (ZERO_VPN2(va) | VPN_TO_VPN2(vpn))
#define SET_VA_VPN1_TO_VPN(va, vpn) (ZERO_VPN1(va) | VPN_TO_VPN1(vpn))

#define CREATE_VPN_FROM_LINE_AND_OFFSET(line, offset) ((line << 3) + offset) 

#define TOP_MASK                    (0b11111111111111111L << 47)
#define ZERO_TOP(va)                (((uint64_t)(va)) & (~TOP_MASK))
#define TOP_TO_INT(va)              (((uint64_t)va & TOP_MASK) >> 48)
#define INT_TO_TOP(line)            (((uint64_t)line) << 48)
#define SET_VA_TOP_TO_INT(va, line) (ZERO_TOP(va) | INT_TO_TOP(line))

#define ignore_mask (~(0b1111111111111111100000111100000111100000111111111111111111111111)) // hand crafted to handle remove one byte shift values 

struct bit_map {
    uint8_t *bytes; 
    int64_t cur_pos;  // the position in the byte mapping 
    uint64_t size; 
}; 

uint64_t get_cur_ptr(struct bit_map *cur); 

struct bit_map *create_bit_map(uint64_t num_of_bytes);

void destroy_bit_map(struct bit_map* to_free);

uint8_t add_ptr_to_bit_map(struct bit_map *map, uint64_t new_info, uint64_t page_walk_depth, uint64_t do_check);

void shift_one_byte(struct bit_map *to_shift);

uint8_t assert_bit_correctness(uint64_t old, uint64_t new, uint64_t page_walk_depth); 

void shift_and_add_one_byte(struct bit_map *map, uint64_t new_info); 

uint64_t get_cur_ptr(struct bit_map *cur); 

void write_ptr_to_map(struct bit_map *map, uint64_t ptr);