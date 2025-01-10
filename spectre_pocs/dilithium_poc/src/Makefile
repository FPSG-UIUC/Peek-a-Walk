CC=clang
CFLAGS += -O3 -g -I../../../pwsc_library/include/ -I../..
SOURCES = sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c fips202.c \
	randombytes.c symmetric-shake.c
HEADERS = config.h params.h api.h sign.h packing.h polyvec.h poly.h ntt.h \
	reduce.h rounding.h symmetric.h randombytes.h fips202.h
EXECS= victim attacker

ARCH=INTEL_13_GEN 
OS=LINUX_v6_6_RC4_UBUNTU

.PHONY: victim attacker all

all: victim attacker

victim: victim.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_RANDOMIZED_SIGNING -DDILITHIUM_MODE=2 -DDEBUG -o $@ $< $(SOURCES)

attacker: attacker.c $(SOURCES) $(HEADERS)
	cp ../../../bin/pwsc.a .
	cp ../../pwsc_spectre_bhi.a .
	$(CC) $(CFLAGS) -DDILITHIUM_RANDOMIZED_SIGNING -DDILITHIUM_MODE=2 -DDEBUG -o $@ $< $(SOURCES) pwsc_spectre_bhi.a pwsc.a -D$(ARCH) -D$(OS)

clean:
	rm -f $(EXECS)
	rm -f pwsc.a pwsc_spectre_bhi.a
