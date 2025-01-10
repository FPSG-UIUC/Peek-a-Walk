obj-m += kernel_mem_scanner.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	clang -O2 -g phys_scanner.c -o phys_scanner.out

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm -rf phys_scanner.out
