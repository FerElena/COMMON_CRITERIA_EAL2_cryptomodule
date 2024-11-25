#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "cryptomodule_core/API_core.h"


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
    printf("el resultado de insertar la clave 1 es : %d\n", result);

    result = API_MC_Insert_Key(key1, 32, key_name2, strlen(key_name2));
    printf("el resultado de insertar la clave 2 es : %d\n", result);

    result = API_MC_Delete_Key(key_name2, strlen(key_name2));
    printf("el resultado de borrar la clave es : %d\n", result);

    result = API_MC_Load_Key(key_name1, strlen(key_name1));
    printf("el resultado de cargar la clave es : %d\n", result);
  
    unsigned char texto_ejemplo[2000000];
    unsigned char aux_buffer[sizeof(texto_ejemplo) + 72];
    unsigned char aux_buffer_2[sizeof(texto_ejemplo)]; 
    size_t out_length_cipher;     
    size_t out_length_decipher;

    for (int i = 0; i < 200000; i++) 
    {

        API_RNG_fill_buffer_random(texto_ejemplo, sizeof(texto_ejemplo));
  
        result = API_MC_Sing_Cipher_Packet(texto_ejemplo, sizeof(texto_ejemplo), aux_buffer, &out_length_cipher);

        printf("el resultado de cifrar el packete es:  %d\n", result);

        result = API_MC_Decipher_Auth_Packet(aux_buffer, out_length_cipher, aux_buffer_2, &out_length_decipher);

        printf("el resultado de descifrar el packete es: %d\n el packete es:   ", result);
        int result = memcmp(aux_buffer_2,texto_ejemplo,sizeof(texto_ejemplo));
        if(result == 0){
            printf("texto de iteración ,%d pasa correcto\n",i);
        }
        else{
            printf("ERROR EN ITERACION %d\n",i);
            break;
        }
    }
 
    API_MC_Shutdown_module();
    usleep(1000000);
    printf("\n");

    return 0;
}