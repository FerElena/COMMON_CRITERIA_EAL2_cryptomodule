#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "cryptomodule_core/API_core.h"
#include "crypto-selftests/selftests.h"
#include "tests/testing_file_system.h"
#include "tests/MemoryTrackerTest.h"
#include "tests/DmemmanagerTest.h"
#include "tests/packet_cipher_authtest.h"
#include "crypto/AES_OFB.h"
#include "secure_memory_management/file_system.h"
#include "library_tracer/log_manager.h"
#include "cryptomodule_core/packet_cipher_auth.h"
#include "prng/random_number.h"

int main()
{
    system("clear");
    printf("prueba inicio modulo\n");
    unsigned char *cryptodata_filename = "cryptodata_test";
    unsigned char *KEK_CERT_fileroute = "/home/ninjahacker/Escritorio/COMMON_CRITERIA_EAL2_cryptomodule/scripts/certificate_manager/testing_cert"; // your route to cert
    int result = API_MC_Initialize_module(KEK_CERT_fileroute, cryptodata_filename);
    printf("el resultado de la inicialización del modulo es : %d\n", result);

    uint8_t key1[32], key2[32];
    API_RNG_fill_buffer_random((unsigned char *)key1, 32);
    API_RNG_fill_buffer_random((unsigned char *)key2, 32);

    unsigned char *key_name1 = "Key1";
    unsigned char *key_name2 = "Key2";

    result = API_MC_Insert_Key(key1, 32, key_name1, strlen(key_name1));
    result = API_MC_Insert_Key(key1, 32, key_name2, strlen(key_name2));
    printf("el resultado de insertar la clave es : %d\n", result);

    result = API_MC_Delete_Key(key_name2, strlen(key_name2));
    printf("el resultado de borrar la clave es : %d\n", result);

    result = API_MC_Load_Key(key_name1, strlen(key_name1));
    printf("el resultado de cargar la clave es : %d\n", result);

    unsigned char texto_ejemplo[] =
        "Este es un ejemplo de texto aleatorio generado para ser utilizado como una cadena de prueba. El contenido de este "
        "texto no tiene ningún significado particular, pero está diseñado para ser legible y tener un tamaño de exactamente "
        "1000 bytes. En este fragmento se incluyen palabras en español, así como una combinación de letras, números y signos "
        "de puntuación. La intención es demostrar cómo se puede construir un bloque de texto que sea completamente legible y "
        "cumpla con los requisitos del tamaño solicitado. A medida que seguimos escribiendo, el texto se llena con oraciones "
        "variadas que siguen una estructura coherente. Sin embargo, debido a la naturaleza de este ejercicio, no se espera "
        "que el contenido sea informativo o útil más allá del propósito de prueba. Esta sección finaliza con más caracteres "
        "para asegurarse de que se completa el número exacto de 1000 bytes, agregando algunas palabras adicionales que "
        "rellenan el espacio necesario y finalizan con un punto.";

    unsigned char aux_buffer[sizeof(texto_ejemplo) + 72];
    unsigned char aux_buffer_2[sizeof(texto_ejemplo)];
    size_t out_length_cipher;
    size_t out_length_decipher;

    result = API_MC_Sing_Cipher_Packet(texto_ejemplo, sizeof(texto_ejemplo), aux_buffer, &out_length_cipher);

    printf("el resultado de cifrar el packete es:  %d\n", result);

    result = API_MC_Decipher_auth_packet(aux_buffer, out_length_cipher, aux_buffer_2, &out_length_decipher);

    printf("el resultado de descifrar el packete es: %d\n el packete es:   ", result);

    for (int i = 0; i < out_length_decipher; i++)
    {
        putchar(aux_buffer_2[i]);
    }
    usleep(1000000);
    printf("\n");

    return 0;
}