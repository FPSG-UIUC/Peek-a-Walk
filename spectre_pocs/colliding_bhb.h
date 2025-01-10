/*
 *  All code credits go to the Inspectre Gadget paper [1]. 
 *  - Alan :) 
 * 
 *  [1] Inspectre Gadget by Weibing et al. https://github.com/vusec/inspectre-gadget  
 */

#ifndef _COLLIDING_BHB_H_
#define _COLLIDING_BHB_H_

#include <unistd.h>

#include "flush_and_reload.h"

void find_colliding_history(struct config * cfg);
int find_hp_kern_address(struct config * cfg, uint64_t only_honey_pages);

#endif //_COLLIDING_BHB_H_
