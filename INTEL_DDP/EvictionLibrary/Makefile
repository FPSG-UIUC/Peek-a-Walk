GCC=clang
FLAGS=-O2 -g

all: cache_measurements

cache_measurements: cache_measurements.c 
	$(GCC) $(FLAGS) cache_measurements.c  -o cache_measurements.out

clean: 
	rm -f *.out
	rm -f *.o
	rm -f *.expanded.c