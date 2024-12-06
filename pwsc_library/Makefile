CC=clang
CFLAGS += -D_GNU_SOURCE -g3 -Wall -Wextra -std=gnu11 -O3 -fPIC
CFLAGS += -Iinclude

.PHONY: all clean 

SRCS=$(wildcard src/*.c)
OBJS=$(foreach s,$(SRCS),$(patsubst src/%.c,build/%.o,$(s)))

all: build/pwsc.a

build/%.o: src/%.c
	mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

build/pwsc.a: $(OBJS)
	mkdir -p build
	ar r $@ $^

clean: 
	rm -rf build

