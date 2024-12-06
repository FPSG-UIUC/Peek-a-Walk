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
Make Version: `GNU Make 4.3`

# Source Code Overview 
* `pwsc_library`: this contains the PWSC library files. 
    * `src`: source code for the library
        * `pwsc.c`: this contains the bulk of the PWSC logic 
        * The other files contain helper / utility functions for `pwsc.c` 
    * `include`: header files for the library
    * `build`: generate build files 
* `src`: this contains the source code that uses the PWSC library files. Right now we only have a simple test called in `arch.c` 

Note: the more advanced PoCs mentioned in our paper are slowly being moved here, so keep a look out for them! 

# Building 
Just simple run `make`! 

# Usage 
Final runnables will be output in `bin/`. After building there should be two items: the PWSC library file and the simple test using that library.

To run the simple test after building you can simple run `./bin/arch.out`. 

# TODOs for this repo 
* The more advanced repos mentioned in our paper 
    * Spectre-V2 PoCs 
    * Intel DDP PoCs 
* Intel DMP RE 

# Acknowledgements 
I would like to acknowledge the Vusec group behind AnC (Gras et al.), this repo started from their open source code [here](https://github.com/vusec/revanc). I would also like to acknowledge the Vusec group behind SLAM (Hertogh et al.) and Inspectre (Wiebing et al.), the spectre code here is mainly based off their open source code [here](https://github.com/vusec/slam) and [here](https://github.com/vusec/inspectre-gadget). 