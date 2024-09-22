ts=$(shell /bin/date "+%d-%m-%Y---%H:%M:%S")

all: testing_common_library

testing_common_library: selftests_main.c crypto/*.c crypto-selftests/*.c state_machine/*.c  library_tracer/*.c secure_memory_management/*.c  tests/*.c prng/*.c cryptomodule_core/*.c
	@echo "($(ts)) Compiling project..."; \
	gcc -pthread $^ -g -o $@; \
	echo "($(ts)) Compilation finished\n";
