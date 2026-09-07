GCC=clang
FLAGS=-O2 -g -fPIC

all: evict_lib test_l1

evict_lib: evict_algorithm.c util.c util.h evict_algorithm.h evict_set.h
	$(GCC) $(FLAGS) -c util.c evict_algorithm.c -Iutil.h -Ievict_set.h
	$(GCC) $(FLAGS) -o evict_lib.so util.o evict_algorithm.o -shared

test_l1: evict_lib test_l1.c 
	$(GCC) $(FLAGS) evict_lib.so test_l1.c -o test_l1.out

clean: 
	rm -f *.out
	rm -f *.o
	rm -f *.expanded.c
	rm -f *.so