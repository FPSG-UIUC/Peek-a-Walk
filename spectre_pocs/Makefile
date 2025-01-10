CFLAGS = -g -O3 -Wno-unused-function -lm -no-pie

# ARCH = undef
# OS = undef
ARCH=INTEL_13_GEN 
OS=LINUX_v6_6_RC4_UBUNTU

LIB=poc-common
INC=-I../pwsc_library/include/

.PHONY: clean pwsc_spectre_bhi_lib victim_physmap dilithium all 

all: pwsc_spectre_bhi_lib main victim_physmap dilithium

pwsc_spectre_bhi_lib: pwsc_spectre_bhi.c flush_and_reload.c colliding_bhb.c ${LIB}/kaslr_prefetch/kaslr_prefetch.c ${LIB}/l2_eviction/evict_sys_table_l2.c snippet.S 
	clang -c snippet.S -o snippet.o
	clang $(INC) -c pwsc_spectre_bhi.c -o pwsc_spectre_bhi.o $(CFLAGS) -D$(ARCH) -D$(OS) 
	clang $(INC) -c flush_and_reload.c -o flush_and_reload.o $(CFLAGS) -D$(ARCH) -D$(OS) 
	clang $(INC) -c colliding_bhb.c -o colliding_bhb.o $(CFLAGS) -D$(ARCH) -D$(OS) 
	clang $(INC) -c ${LIB}/kaslr_prefetch/kaslr_prefetch.c -o kaslr_prefetch.o $(CFLAGS) -D$(ARCH) -D$(OS) 
	clang $(INC) -c ${LIB}/l2_eviction/evict_sys_table_l2.c -o evict_sys_table_l2.o $(CFLAGS) -D$(ARCH) -D$(OS) 
	ar r pwsc_spectre_bhi.a pwsc_spectre_bhi.o flush_and_reload.o colliding_bhb.o kaslr_prefetch.o evict_sys_table_l2.o snippet.o 

main: main.c pwsc_spectre_bhi_lib
	rm -rf pwsc.a 
	cp ../bin/pwsc.a .
	clang $(INC) main.c pwsc_spectre_bhi.a pwsc.a -o main $(CFLAGS) -D$(ARCH) -D$(OS) 

victim_physmap: victim_physmap.c 
	clang $(INC) victim_physmap.c -o victim_physmap $(CFLAGS)

dilithium: 
	make -C ./dilithium_poc/src/

clean:
	rm -f main victim_physmap attacker victim
	rm -f *.o 
	rm -f *.a
	make -C ./dilithium_poc/src/ clean
