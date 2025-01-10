CC=clang
CFLAGS += -D_GNU_SOURCE -g3 -Wall -Wextra -std=gnu11 -O3 -fPIC
CFLAGS += -Iinclude -Ipwsc_library/include -no-pie

SRCS=$(wildcard src/*.c)
PROGS=$(foreach s,$(SRCS),$(patsubst src/%.c,bin/%.out,$(s)))
TESTS_SRC=$(wildcard tests/*.c)
TESTS_PROGS=$(foreach s,$(TESTS_SRC),$(patsubst tests/%.c,tests_bin/%.out,$(s)))

.PHONY: all clean pwsc_library spectre_pocs tools

all: $(PROGS) $(TESTS_PROGS) spectre_pocs tools

pwsc_library: 
	make -C pwsc_library 
	mkdir -p bin 
	mv pwsc_library/build/pwsc.a bin/

bin/%.out: src/%.c pwsc_library
	mkdir -p bin 
	$(CC) $(CFLAGS) $< bin/pwsc.a -o $@

tests_bin/%.out: tests/%.c pwsc_library
	mkdir -p tests_bin 
	$(CC) $(CFLAGS) $< bin/pwsc.a -o $@

spectre_pocs: pwsc_library
	make -C spectre_pocs

tools:
	make -C tools

clean: 
	make -C pwsc_library clean
	make -C spectre_pocs clean
	make -C tools clean
	rm -rf bin/ 
