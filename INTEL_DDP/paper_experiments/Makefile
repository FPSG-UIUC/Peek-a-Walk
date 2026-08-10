GCC=clang
FLAGS=-O2 -g
HEADERS=-I../util/util.h

.PHONY: all clean

SRCS = $(wildcard *.c)
PROGS = $(patsubst %.c,%,$(SRCS))

all: $(PROGS)

%: %.c
	$(GCC) $(FLAGS) $(HEADERS) ../util/util.c ../bunnyhop/bunnyhop.c -o $@.out $^

clean:
	rm -f *.out
	rm -f *.o
	rm -f *.expanded.c