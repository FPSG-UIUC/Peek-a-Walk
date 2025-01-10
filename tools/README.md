# Tooling 
This folder contains various tools used for our paper Peek-a-Walk 

# Additional Tools
A tool not in this repo is the LiME tool: https://github.com/504ensicsLabs/LiME.git 

We use this tool to create kernel physmap dumps used in our paper to generate Table 1. 

# Building
Simply run `make`! 

# Usage
There are two tools currently included in this folder. 

1) `kernel_mem_scanner.ko`: Is our kernel module to allow anyone in userland to read from kernel memory. To install it simply insert the module into the kernel. The user then writes an address in `/proc/mem_scanner_tool/scan_mem` and reads from `/proc/mem_scanner_tool/scan_mem` to find the 8 byte value at that address. This tool is used in our dilithium leak to verify that we are fetching the correct nonces from the victim. 
2) `phys_scanner.out`: This is the tool used to generate Table 1 in our paper. After fetching a binary dump of physmap from LiME, you can feed the dump into this tool to generate similar stats to Table 1 in our paper. 