#include <stdio.h>
#include "crypto-selftests/selftests.h"
#include "tests/testing_file_system.h"
#include "tests/MemoryTrackerTest.h"
#include "tests/DmemmanagerTest.h"
#include "crypto/AES_OFB.h"
#include "file_system/file_system.h"
#include "library_tracer/log_manager.h"
#include "packet_manager/packet_cipher_auth.h"

int main(){
    system("clear");
    printf("prueba inicio selftests\n");
    API_SFT_initSelfTests();
    FS_testing();
    MemoryTracker_tests();
    Test_DmemManager();

    unsigned char data_in[30001] = "This is a test message for enfdsfsdfsdfsdfsdfsdfcryption"; // Mensaje de prueba, a partir de tamaño 1024 me falla no se porque
    size_t data_in_length = sizeof(data_in);
    
    unsigned char key_AES[32] = {0};  // Clave AES de 256 bits
    unsigned char key_HMAC[32] = {0}; // Clave HMAC de 256 bits  
    
    unsigned char *encrypted_data; // Buffer para el dato cifrado
    size_t encrypted_data_length = 0;
   
    unsigned char *decrypted_data; // Buffer para el dato descifrado
    unsigned char verify = 0;

    // Llamada a la función de cifrado
    int encrypt_status = API_PCA_sign_encrypt_packet(data_in, data_in_length, key_AES, key_HMAC, &encrypted_data, &encrypted_data_length);
    if (encrypt_status != 1) {
        printf("Error in encryption\n");
        return -1;
    }

    printf("Encryption successful! Encrypted data length: %zu\n", encrypted_data_length);

	printf("\n");

    // Llamada a la función de descifrado
    int decrypt_status = API_PCA_decrypt_verify_packet(encrypted_data, encrypted_data_length, key_AES, key_HMAC, &decrypted_data, &verify);
    if (decrypt_status != 1) {
        printf("Error in decryption\n");
        return -1;
    }
  
    // Verificación del resultado
    if (verify != 1) {
        printf("Verification failed!\n");
        return -1;
    }

    // Comparar datos originales con los datos descifrados
    if (memcmp(data_in, decrypted_data + 32, data_in_length) == 0) {
        printf("The decrypted message matches the original message!\n");
    } else {
        printf("The decrypted message does not match the original message!\n");
    }

    return 0;
    
    
    
    return 0;
}