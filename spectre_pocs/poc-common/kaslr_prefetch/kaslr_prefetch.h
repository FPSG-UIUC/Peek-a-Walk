/*
 *  All code credits go to the Inspectre Gadget paper [1]. 
 *  - Alan :) 
 * 
 *  [1] Inspectre Gadget by Weibing et al. https://github.com/vusec/inspectre-gadget  
 */
#ifndef _KASLR_PREFETCH_H_
#define _KASLR_PREFETCH_H_

#include <stdint.h>

uint64_t find_section_start(uint64_t start, uint64_t end, uint64_t alignment);
uint64_t find_phys_map_start();
void initialize_kaslr_prefetch();

#endif //_PHYS_MAP_H_
