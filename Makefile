ts=$(shell /bin/date "+%d-%m-%Y---%H:%M:%S")

# Default target
all: testing_cryptomodule

# Compile the testing_cryptomodule executable
testing_cryptomodule: Code_testing.c crypto/*.c crypto-selftests/*.c state_machine/*.c library_tracer/*.c secure_memory_management/*.c tests/*.c prng/*.c cryptomodule_core/*.c
	@echo "($(ts)) Compiling project..."; \
	gcc -pthread $^ -g -o $@; \
	echo "($(ts)) Compilation finished\n"; \
	echo "($(ts)) Running key_cert_generator for executable..."; \
	cd scripts/certificate_manager && ./key_cert_generator -cg ecdsa_keypair ../../testing_cryptomodule testing_cert; \
	echo "($(ts)) key_cert_generator executed successfully for executable\n";

# Compile the static library without testing_main.c
static_lib: crypto/*.c crypto-selftests/*.c state_machine/*.c library_tracer/*.c secure_memory_management/*.c prng/*.c cryptomodule_core/*.c
	@mkdir -p XLibrary_crypto  # Crear el directorio si no existe
	@echo "($(ts)) Compiling static library..."; \
	gcc -pthread -c $^ -g; \
	ar rcs XLibrary_crypto/libcryptomodule.a *.o; \
	rm -f *.o; \
	echo "($(ts)) Static library XLibrary_crypto/libcryptomodule.a created\n"; \
	echo "($(ts)) Running key_cert_generator for static library..."; \
	cd scripts/certificate_manager && ./key_cert_generator -cg ecdsa_keypair ../../XLibrary_crypto/libcryptomodule.a static_cert; \
	echo "($(ts)) key_cert_generator executed successfully for static library\n";

# Clean generated files
clean:
	rm -f testing_cryptomodule XLibrary_crypto/libcryptomodule.a *.o
