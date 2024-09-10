#include "packet_cipher_authtest.h"

// Función para generar un número aleatorio entre min y max
size_t random_size_t(size_t min, size_t max) {
    return (rand() % (max - min + 1)) + min;
}

// Función para probar cifrado y descifrado de un solo mensaje, esta mal poeque no libera memoria
int test_encrypt_decrypt(unsigned char *plaintext, size_t plaintext_length, unsigned char *key_AES, unsigned char *key_HMAC) {
    unsigned char *ciphertext = NULL;
    size_t ciphertext_length;
    unsigned char *decrypted_plaintext = NULL;
    unsigned char verify;

    // Cifrar y firmar el mensaje
    int result1 = API_PCA_sign_encrypt_packet(plaintext, plaintext_length, key_AES, key_HMAC, &ciphertext, &ciphertext_length);
    if (result1 != NOT_ALLOCATED_MEMORY && result1 != ALLOCATED_MEMORY) {
        printf("Fallo en la función de cifrado y firma\n");
        return 0;
    }

    // Descifrar y verificar el mensaje, el valor de la firma se guarda en `verify`
    int result2 = API_PCA_decrypt_verify_packet(ciphertext, ciphertext_length, key_AES, key_HMAC, &decrypted_plaintext, &verify);
    if (result1 != NOT_ALLOCATED_MEMORY && result1 != ALLOCATED_MEMORY) {
        printf("Fallo en la función de descifrado y verificación\n");
        return 0;
    }

    // Verificar que el valor de `verify` sea correcto (1 para éxito)
    if (verify != 1) {
        printf("Fallo en la verificación HMAC\n");
        return 0;
    }

    // Comprobar si los datos descifrados coinciden con el texto plano original
    if (memcmp(plaintext, decrypted_plaintext, plaintext_length) != 0) {
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
    fill_buffer_with_random_bytes(key_AES, sizeof(key_AES));
    fill_buffer_with_random_bytes(key_HMAC, sizeof(key_HMAC));

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
        fill_buffer_with_random_bytes(plaintext, plaintext_length);

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