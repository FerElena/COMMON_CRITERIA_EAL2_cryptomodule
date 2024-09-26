#include "packet_cipher_authtest.h"

// Función para generar un número aleatorio entre min y max
size_t random_size_t(size_t min, size_t max) {
    return (rand() % (max - min + 1)) + min;
}

// Función para probar cifrado y descifrado de un solo mensaje, esta mal poeque no libera memoria
int test_encrypt_decrypt(unsigned char *plaintext, size_t plaintext_length, unsigned char *key_AES, unsigned char *key_HMAC) {
    unsigned char *ciphertext = NULL;
    size_t ciphertext_length,plaintext_length_aux;
    unsigned char *decrypted_plaintext = NULL;
    unsigned char verify;
    unsigned char aux_test_buff[ 4 * 1024 * 1024];

    // Cifrar y firmar el mensaje
    int result1 = API_PCA_sign_encrypt_packet(plaintext, plaintext_length, key_AES, key_HMAC, &ciphertext, &ciphertext_length);
    if (result1 != NOT_ALLOCATED_MEMORY && result1 != ALLOCATED_MEMORY) {
        printf("Fallo en la función de cifrado y firma\n");
        return 0;
    }
    memcpy(aux_test_buff,ciphertext,ciphertext_length);
    if(result1 == ALLOCATED_MEMORY)
        API_MM_freeMem(ciphertext);

    // Descifrar y verificar el mensaje, el valor de la firma se guarda en `verify`
    int result2 = API_PCA_decrypt_verify_packet(aux_test_buff, ciphertext_length, key_AES, key_HMAC, &decrypted_plaintext,&plaintext_length_aux, &verify);
    if (result2 != NOT_ALLOCATED_MEMORY && result2 != ALLOCATED_MEMORY) {
        printf("Fallo en la función de descifrado y verificación\n");
        return 0;
    }
    memcpy(aux_test_buff,decrypted_plaintext ,plaintext_length_aux);
    if(result2 == ALLOCATED_MEMORY)
        API_MM_freeMem(decrypted_plaintext);

    // Verificar que el valor de `verify` sea correcto (1 para éxito)
    if (verify != 1) {
        printf("Fallo en la verificación HMAC\n");
        return 0;
    }

    // Comprobar si los datos descifrados coinciden con el texto plano original
    if (memcmp(plaintext, aux_test_buff, plaintext_length) != 0) {
        printf("El texto plano descifrado no coincide con el original\n");
        return 0;
    }

    return 1;  // El test fue exitoso
}

// Función para ejecutar 10,000 pruebas de cifrado y descifrado
void run_tests_packets(int num_times) {
    // Inicializar las claves AES y HMAC de 256 bits
    unsigned char key_AES[32];  // Clave de 256 bits
    unsigned char key_HMAC[32];  // Clave de 256 bits

    // Llenar las claves con valores aleatorios
    API_RNG_fill_buffer_random(key_AES, sizeof(key_AES));
    API_RNG_fill_buffer_random(key_HMAC, sizeof(key_HMAC));

    // Configurar la generación aleatoria de números
    srand((unsigned int)time(NULL));

    // Probar 10,000 textos planos aleatorios
    for (int i = 0; i < num_times; i++) {
        // Generar un tamaño aleatorio entre 1 byte y 4 MB
        size_t plaintext_length = random_size_t(1, 4 * 1024 * 1024);  // Entre 1 byte y 4MB
        unsigned char *plaintext = malloc(plaintext_length);

        if (!plaintext) {
            printf("Error al asignar memoria para el texto plano\n");
            exit(-1);
        }

        // Llenar el texto plano con datos aleatorios
        API_RNG_fill_buffer_random(plaintext, plaintext_length);

        // Probar el cifrado/descifrado del texto plano
        printf("Test #%d - Longitud del texto plano: %zu bytes\n", i + 1, plaintext_length);
        if (!test_encrypt_decrypt(plaintext, plaintext_length, key_AES, key_HMAC)) {
            printf("Fallo en el test #%d\n", i + 1);
            free(plaintext);
            exit(-1);
        }

        // Liberar la memoria del texto plano
        free(plaintext);
    }

    printf("Todos los tests pasaron correctamente.\n");
}