# Overview
Below is a explaination for each expirment (.c file) as well as and explaination on the usage and results gather on both Intel i9 and Xeon CPUs.

### Each expirment generally contains the following structures.

- `training_aop`, stands is array of pointers (aop) used for training and each index coressponds to an index in `train_buffer` that conatins random values that looks like canonical pointers (upper 16 bits are all 0's). The DMP is trained by conducting a "double deference", where both the training_aop index and training_buffer values are loaded from memory via the function acess_aop().

- `test_aop`, similar to the `training_aop`, each index points to a coresspoinding index in `test_buffer` that contains a canonical value. 

- `ptr_under_test` this is a canonical pointer with a fixed virtual address via `mmap` with a value of `0xDEADBEEF` that lives within a index of `test_aop`. The access time of `ptr_under_test` tells us if the DDP has pulled the data into memory (fast hit) verus not (slow hit).

- `access_aop()` an inline function that 

### Setup:
- Each expirment in pinned to a sepcific logical CPU and all aops are initalized.  

### Timing Trial Loop:
Each iteration of the trial loop contains the following:
- Training DDP via double deferencing the `train_aop`.
- DDP activation via `access_size` number of single deference in `test_aop`.
- Timing access time of `ptr_under_test` or `NULL` depending on even or odd trial number to record background noise. 

### Data Logging

# Expirments
## prefetch_distance.c

Test how far the DMP will prefetch given access_size (number of single deferences starting from 0th index in test_aop), test_ptr location (index which the ptr_under_test lives in test_aop), and access stride. The training is fixed at 350.

#### Inputs
- access_size
- test_ptr_location
- stride

## training_len_flush.c
To demostrate that flushing the `training_aop` between trials drastically decreases the needed training_len.

#### Inputs
- training_len
- Need to fix trainng_len.c loki, smth is broken

## pc.c
Tests PC aliasing in the DMP. The training load sits at `DEFAULT_BASE + pc_train_relative`; the trigger load sits at `DEFAULT_BASE + pc_train_relative + pc_test_offset`. Because the DMP indexes on the low 10 bits of the load PC, sweeping `pc_test_offset`, with `pc_train_relative` fixed, produces hits only when the two PCs share those bits (every multiple of 1024 for 10 bit aliasing).

#### Inputs
- `pc_train_relative` 
- `pc_test_offset` 

