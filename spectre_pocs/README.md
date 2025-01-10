# SpectreV2 BHI PoCs 
This folder contains all the SpectreBHI PoCs in our Peek-a-Walk paper. 
SpectreBHI is the first case study in our Peek-a-Walk paper that showcases expanded attacker capabitilies of the SpectreBHI threat model with our new, powerful, PWSC. 

# Building
1. Run `make` in the root repo directory to create a `pwsc.a` static library in `bin`. This is used by our Spectre PoCs 
2. Just simply run `make` on this folder! 

**Note**: You may need to run `./poc-common/install_dependencies.sh` to install the necessary dependencies first. 

# Linux Kernel Changes
Follow the instructions [here](https://github.com/vusec/inspectre-gadget/tree/main/experiments/native-bhi) (Inspectre Gadget kernel instructions for Linux 6.6 rc4).

To configure the kernel to simulate Intel LAM you can **manually** apply the patch from SLAM [here](https://github.com/vusec/slam/tree/main/kernel). **Do not** follow the instructions as the kernel version don't match. You need to **manually** apply `lam.patch`. 

# Usage  
!!!!!! **Important**: If you running these PoCs for the first time you will need to run `sudo ./setup.sh` this ensures cgroup operations are available. 

!!!!!! **Important**: There are several PoCs, in order to build and run these PoCs you need to run `sudo ./run.sh`. 
This will call the `main` (`main.c`) to run the coded PoC. 
To change which PoC runs, modify `main.c` to use the correct PoC (for ease all PoCs are commented out). 
Our Dilithium PoC (doesn't require Intel LAM / kernel modifications) is contained in `attacker.c` with the Dilithium victim in `victim.c`. 

The full list of PoCs in `main.c` is as follows,
1) In `main.c`, `pwsc_test()`: leaking 8 bytes using the PWC order oracle from the kernel. 
2) In `main.c`, `leak_etc_shadow()`: Leaking /etc/shadow. Requires Intel LAM to be added to the kernel and requires inputting the physmap address /etc/shadow.
3) In `main.c`, `leak_ascii()`: Leaking ASCII strings from a victim process. Requires Intel LAM to be added to the kernel and requires inputting the physmap address of the ASCII string. A victim is provided and can be started by running `sudo ./victim_physmap`. 
4) In `main.c`, `test_leak_u64()`: This will add a 8 byte secret in the kernel and leak it with the `leak_u64()` function. 
5) In `main.c`, `paper_stats()`: This generates the stats used in Table 2 of our paper. It leaks a set of interesting kernel bytes with Intel LAM enabled. 

Our Dilithium PoC is not in `main.c` but in `dilithium_poc` and **does not require Intel LAM** to be enabled. The following subsection describes our Dilithium PoC more. 

## Dilithium PoC 
To run the Dilithium PoC, first go to `root_dir/tools` and follow the `README.md` instructions to insert the `kernel_mem_scanner.ko` kernel module. This is not required to run the PoC but will help ensure that you don't run LWE forever as it checks to make sure all the leaked coefficients are correct. After inserting the kernel module run the following,

Terminal 1
1) `cd dilithium_poc/src/`
2) `./victim` 

Terminal 2
1) `cd dilithium_poc/src/`
2) `sudo ./attacker <PID of victim> <address of y>`
Both `<PID of victim>` and `<address of y>` are printed to stdout by `victim`.

After the attacker process collects enough hints in do the following,

Terminal 3
1) `cd dilithium_poc/`
2) `python dilithium_lattice_reduction.py` which should run LWE to extract the secret key from the leaked coefficients. 

# Files 
* `poc-common` `colliding_bhb.*` `flush_and_reload.*` `snippet.S` `targets.h`: these are files needed for SpectreBHB. Refer to Inspectre Gadget for more details [here](https://github.com/vusec/inspectre-gadget).
* `pwsc_spectre_bhi.*`: contains is the static library that houses all the SpectreBHB + PWSC leakage functions. 
* `main.c`: is our simple test code to run functions in `pwsc_spectre_bhi` 
* `victim_physmap.c`: is the victim process where ASCII strings are leaked from 
* `dilithium_poc`: houses all the dilithium PoC code
    * `dilithium_lattice_reduction.py`: the LWE code that takes leaked nonce coefficients to extract the Dilithium secret key
    * `src/`
        * `victim.c`: The Dilithium victim
        * `attacker.c`: The Dilithium attacker 