# Overview

The following files attempt to test safety features at the operating system (OS), compiler, and hardware level to mitigate/prevent DDP side-channel attacks.

## doitm.c
Data Operand Independent Timing Mode (DOITM) is an Intel CPU setting that forces a subset of instructions to run in constant, data-independent time. This file uses a helper thread to flip DOITM on before testing whether it suppresses the DDP on `ptr_under_test`.

### Inputs
- `core id` — CPU core to pin to
- `reps` — number of measurement rounds
- `out of bounds read idx` — how far past the array end the target is planted

## pku.c
Protection Keys for Userspace (PKU) allows fast access-permission changes to pages. The page holding the target pointer is locked with `PKEY_DISABLE_ACCESS` before the victim runs, and the code checks whether the DDP dereferenced it anyway. This tests whether locking the data prevents the DDP from prefetching it.

### Inputs
- `core id` — CPU core to pin to
- `reps` — number of measurement rounds
- `out of bounds read idx` — how far past the array end the target is planted

## aslr.c
Tests whether the DDP can be used as a mapped-vs-unmapped oracle to defeat ASLR. Memory layout cannot be probed normally because dereferencing an unmapped guess crashes the process. However, because the DDP dereferences speculatively, an invalid guess is silently dropped without a crash while a mapped address is pulled into cache. Here, `target_va` is deliberately mapped, and the test steers the DDP onto it (strided training + self-modifying code to run the touch speculatively), then times `ptr_under_test` to confirm the DDP fires on a mapped address.

### Inputs
- `core id` — CPU core to pin to
- `reps` — number of measurement rounds
- `sort output` — `1` sorts the attack timings

## poc.c
Proof of concept for a cross-thread attack. The main thread acts as an attacker that trains the DDP and checks whether the DDP will dereference data within the victim thread.

### Inputs
- `core id` — CPU core to pin to
- `repetitions` — number of measurement rounds
- `training size` — number of pointers trained on
- `sort output?` — `1` sorts the attack timings

## prime_probe.c
An L1 prime+probe receiver. A 12-way eviction set is constructed so that `0x667000000000` (`secret_ptr` VA) maps to the set. The loop primes 12 ways and checks which lines are evicted.

### Inputs
- None — core, trial count, and target set are hardcoded

## process.c
Same design as `poc.c`, but selectable between a thread or a true process via `CROSS_PROCESS` (compile-time macro). The parent trains a PC-aliased gadget at `child_process_work + 0x68`. The attack phase (with training) and base phase (no training) run as two separate loops rather than interleaved.

### Inputs
- `core id` — CPU core to pin to
- `repetitions` — number of measurement rounds
- `training size` — number of pointers trained on
- `sort output?` — `1` sorts the attack timings

## slh_all.c
Speculative Load Hardening (SLH) is a compiler-level defense against Spectre v1-style attacks. This test evaluates its effect on the DDP. The `TRAIN` macro unrolls ~256 training loads into straight-line, branchless code, with `ptr_under_test` planted out-of-bounds at `training_aop[training_aop_size + oob_idx]`.

### Inputs
- `out of bounds read idx` — how far past the array end the target is planted

## transient_activation.c
Tests whether a purely transient load (a load executed and then squashed due to mis-speculation) can trigger an already-trained DDP. The DDP is first trained normally. Right before running on `target_aop`, the load is overwritten with NOPs via `set_to_none_inst`, ensuring the pointer is never architecturally loaded. The NOP store is delayed by an `imul` chain to extend the speculation window for the load.

### Inputs
- `core id` — CPU core to pin to
- `reps` — number of measurement rounds
- `training size` — number of pointers trained on
- `test_ptr_after` — legacy target-placement knob
- `num diff ptrs` — number of distinct training pointers
- `thrash size` — accesses used to disturb DDP state
- `unique thrash ptrs?` — whether thrash uses unique pointers
- `confidence thrash size` — accesses used to evict the confidence table
- `sort output?` — `1` sorts the attack timings

## transient_training.c
Uses the same self-modifying code technique as `transient_activation.c`, but trains transiently to test whether the DDP can be trained from scratch using loads that only execute speculatively and never commit.

### Inputs
- Same as `transient_activation.c` (`core id`, `reps`, `training size`, `test_ptr_after`, `num diff ptrs`, `thrash size`, `unique thrash ptrs?`, `confidence thrash size`, `sort output?`)

## thread.c
Tests cross-thread training and the DDP's PC confidence table. Sixteen copies of the same load-and-dereference gadget at different instruction addresses are tested simultaneously to evaluate if the DDP can hold up to 16 PC-tagged entries. Each trial round spawns a fresh `thread_work` thread that trains `access_aop1` on a buffer; the main thread then runs that same PC (`access_aop1`) on `target_aop` and measures `ptr_under_test` to verify cross-thread training.

### Inputs
- Same as `transient_activation.c` (`core id`, `reps`, `training size`, `test_ptr_after`, `num diff ptrs`, `thrash size`, `unique thrash ptrs?`, `confidence thrash size`, `sort output?`)

## sys_call.c
Tests whether executing a system call between training and testing triggers a DDP flush.

### Inputs
- None

## SMT_attacker.c
Tests whether an SMT sibling process pinned to the same physical core can train and induce the DDP to dereference a pointer in the victim process.

### Inputs
- `training_size` — number of pointers trained on

## SMT_victim.c
Times its own `ptr_under_test` to determine if the `SMT_attacker` sibling induced a DDP dereference. Timing is synchronized via barriers.

### Inputs
- `access_size` — number of single load activations
- `test_offset` — offset where `ptr_under_test` is planted in `test_aop`

## SMT_shared.c / SMT_shared.h
Shared resources such as barrier data types and helper functions.