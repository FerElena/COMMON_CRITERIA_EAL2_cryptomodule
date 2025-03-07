# Timestamp for logging
ts=$(shell /bin/date "+%d-%m-%Y---%H:%M:%S")

# Source code
SRC = src/crypto/*.c src/crypto-selftests/*.c src/state_machine/*.c src/library_tracer/*.c src/secure_memory_management/*.c \
src/prng/*.c src/cryptomodule_core/*.c src/API_core.c

# Test source code
TEST_SRC = tests/unit_testing/secure_memory_management_utests/*.c tests/unit_testing/SFT_utest/* tests/unit_testing/utests_main.c 

# Default target
all: testing_cryptomodule

# Compile the testing_cryptomodule executable, and generate the certificate for that one executable with the cryptomodule
testing_cryptomodule: $(SRC) Code_testing.c
	@echo "($(ts)) Compiling project..."; \
	echo "Fuentes:" $(SRC); \
	gcc -pthread $^ -g -maes -march=native -o $@; \
	echo "($(ts)) Compilation finished\n"; \
	echo "($(ts)) Running key_cert_generator for executable..."; \
	cd utils/certificate_manager && ./key_cert_generator -cg ecdsa_keypair ../../testing_cryptomodule testing_cert; \
	echo "($(ts)) key_cert_generator executed successfully for executable\n";

# Compile the static library without testing_main.c
static_lib:  src/crypto-selftests/*.c src/crypto/*.c src/state_machine/*.c src/library_tracer/*.c src/secure_memory_management/*.c src/prng/*.c src/cryptomodule_core/*.c src/API_core.c
	@mkdir -p XLibrary_crypto  # Crear el directorio si no existe
	@echo "($(ts)) Compiling static library..."; \
	gcc -pthread -maes -march=native -c $^; \
	ar rcs XLibrary_crypto/libcryptomodule.a *.o; \
	rm -f *.o; \
	echo "($(ts)) Static library XLibrary_crypto/libcryptomodule.a created\n"; \
	echo "($(ts)) Running key_cert_generator for static library..."; \
	cd utils/certificate_manager && ./key_cert_generator -cg ecdsa_keypair ../../XLibrary_crypto/libcryptomodule.a static_cert; \
	echo "($(ts)) key_cert_generator executed successfully for static library\n";
	cp src/API_core.h XLibrary_crypto/

# Unitary testing of the submodules (checklib must be instaled in order to work)
unitary_test: $(SRC) $(TEST_SRC)
	@echo "($(ts)) Compiling unitary testing..."; \
	echo "Fuentes:" $(SRC); \
	echo "Fuentes de Test:" $(TEST_SRC); \
	gcc -march=native -I/usr/include/check -I. $(SRC) $(TEST_SRC) -o $@ -g -lcheck -lm -lpthread -lrt -lsubunit -pthread -maes ;

# Clean generated files
clean:
	@echo "($(ts)) Cleaning up generated files..."
	# Remove the main executable
	rm -f testing_cryptomodule
	# Remove Cryptodata
	rm -f cryptodata_test 
	# Remove the static library and intermediate object files
	rm -rf XLibrary_crypto
	# Remove any object files from the source directories
	find src/crypto src/crypto-selftests src/state_machine src/library_tracer src/secure_memory_management tests src/prng src/cryptomodule_core -name "*.o" -exec rm -f {} +
	# Remove any certificates generated by the key_cert_generator script
	find utils/certificate_manager -name "*_cert" -exec rm -f {} +
	# Remove unitary testing executable
	rm -r unitary_test
	@echo "($(ts)) Clean completed."
