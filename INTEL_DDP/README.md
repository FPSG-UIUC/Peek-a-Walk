# Intel DDP Reverse Engineering

The code here was used to characterize the behavior of Intel's Data-Memory Dependent Prefetcher (DDP/DMP) as overviewed in Section 5 of the paper.


# Source Code Overview
Each folder contains a seperate md file that explain each expirment, usage, and results more in depth :)

Please note most the files are original source code written by `Alan Wang / urd00m` for the paper with some clean up. All files marked with `[N]` are from `JonathanSHJ` and was used in some post-paper RE efforts on new Intel CPUs.

- `paper_experiments`
    - `prefetch_distance.c` 
    - `training_len_flush.c` `[N]`
    - `pc.c` `
    - `indirect.c` 
    - `linked_list.c`
    - `scripts` `all [N]`
        - `indirect_sweep.py`
        - `linked_list_sweep.py`
        - `pc_sweep.py`
        - `prefetch_distance.py`
        - `training_len_sweep.py`
        - `images`
        - `results.MD`
    - `Makefile` 
    - `README.md` 

- `cross_process_experiments` 
    - `aslr.c` 
    - `doitm.c` 
    - `pku.c` 
    - `poc.c` 
    - `primeprobe.c` 
    - `process.c` 
    - `slh_all.c` 
    - `slh_just_test.c` 
    - `thread.c` 
    - `transient_activation.c` 
    - `transietn_training.c` 
    - `sys_call.c` `[N]`
    - `SMT_shared.c/.h` `[N]`
    - `SMT_vicitm.c` `[N]`
    - `SMT_attacker.c` `[N]`
    - `Makefile`
    - `README.md`

- `bunnyhop`
    - `bunnyhop.c/.h` 
    - `README.md` 

- `EvictionLibrary`
    - `evict_lib`
        - `Makefile`
        - `evict_algorithm.c/.h`
        - `test_l1.c`
        - `util.c/.h`
        - `evict_set.h`
    - `cache_measurements.c`
    - `plot.ipynb`
    - `README.md`

- `Makefile`
- `README.md`

# Building and Usage
Just simply run `make`! 
There are also helpful Python scripts for each experiments. 


