# Peek-a-Walk 
This is the repository for our IEEE S&P 2025 paper: "Peek-a-Walk: Leaking Secrets via Page Walk Side Channels". Checkout our [paper](https://gofetch.fail/files/peek-a-walk.pdf) for more information.

# Introduction 
Peek-a-Walk is a microarchitectural side-channel attack that can extract secrets from the page walk process. 

By monitoring a secret dereference (where secret doesn’t need to be a valid pointer), the page walk side channel (PWSC) can leak up to 42 of the 64 secret bits. This far exceeds the bit leakage of and operates under fewer assumptions than prior memory-based side channels.

We demonstrate how to use PWSC to mount Spectre-V2 attacks that leak up to the entire kernel memory on Intel CPUs with Linear Address Masking (LAM) and Dilithium cryptographic keys on Intel CPUs without LAM. 

Finally, we reverse engineer the semantics of Intel’s data-memory dependent prefetcher (DMP) and demonstrate how this DMP and PWSC can be combined to break security in an intra-process sandbox setting.

# Tool Versioning
Linux Disto: `Ubuntu 22.04.4 LTS`\
Kernel Version: `6.6.0-rc4`\
Processor: `13th Gen Intel Core i9-13900K`\
Make Version: `GNU Make 4.3`\
Clang Version: `14.0.0-1ubuntu1.1` 

# Source Code Overview 
* `pwsc_library`: this contains the PWSC library files. 
    * `src`: source code for the library
        * `pwsc.c`: this contains the bulk of the PWSC logic 
        * `leak.c`: this contains the memory order oracle and the main functions we use in our paper to leak secrets
        * The other files contain helper / utility functions for `pwsc.c` and `leak.c` 
    * `include`: header files for the library
    * `build`: generate build files 
* `src`: this contains the source code that uses the PWSC library files. 
    * `arch.c`: This contains a basic PWC order oracle test with an architectural transmitter
    * `spectre_user.c`: In this test, PWSC uses a Spectre-V2 unmasked gadget to leak a string with the leak userspace pointer function
    * `spectre_ascii.c`: In this test, PWSC uses a Spectre-V2 unmasked gadget to leak a string with the leak ASCII function
    * Expecting two more tests to be slowly ported here (DDP and another Spectre-V2 one)
* `spectre_pocs`: houses the SpectreBHB PoCs refer [here](spectre_pocs/README.md) for more details. 
* `tools`: houses tools used for our paper refer [here](tools/README.md) for more details. 

Note: the more advanced PoCs mentioned in our paper are slowly being moved here, so keep a look out for them! 

# Building 
Just simply run `make`! 

# Usage 

## PWSC Library Tests
Final PWSC library runnables will be output in `bin/`. After building there should be four items: the PWSC library file and the various test binaries which are as follows,
* To run the simple test after building you can simply run `./bin/arch.out`. 
* To test the leak userspace pointer function from `leak.c` simply run `./bin/spectre_user.out`. 
* To test the leak ascii function from `leak.c` simply run `./bin/spectre_ascii.out`. 

## Spectre PoCs
Refer to the `spectre_pocs`'s `README.md` for more details [here](spectre_pocs/). 

## Tools
Refer to the `tools`'s `README.md` for more details [here](tools/). 

## TODO need to add the Intel DMP PoC and the Intel DMP reverse engineering code

# Acknowledgements 
I would like to acknowledge the Vusec group behind AnC (Gras et al.), this repo started from their open source code [here](https://github.com/vusec/revanc). I would also like to acknowledge the Vusec group behind SLAM (Hertogh et al.) and Inspectre (Wiebing et al.), the spectre code here is mainly based off their open source code [here](https://github.com/vusec/slam) and [here](https://github.com/vusec/inspectre-gadget). 
