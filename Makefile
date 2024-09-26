ts=$(shell /bin/date "+%d-%m-%Y---%H:%M:%S")

all: testing_cryptomodule

testing_cryptomodule: testing_main.c crypto/*.c crypto-selftests/*.c state_machine/*.c  library_tracer/*.c secure_memory_management/*.c  tests/*.c prng/*.c cryptomodule_core/*.c
	@echo "($(ts)) Compiling project..."; \
	gcc -pthread $^ -g -o $@; \
	echo "($(ts)) Compilation finished\n"; \
	echo "($(ts)) Running key_cert_generator..."; \
	cd scripts/certificate_manager && ./key_cert_generator -cg ecdsa_keypair ../../testing_cryptomodule testing_cert; \
	echo "($(ts)) key_cert_generator executed successfully\n";
