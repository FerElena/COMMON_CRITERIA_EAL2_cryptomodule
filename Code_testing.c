#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include "src/API_core.h"
#include "src/crypto/AES_GCM.h"

int main()
{

    system("clear");
    printf("prueba inicio modulo\n");

    /*
    unsigned char *cryptodata_filename = "cryptodata_test";
    unsigned char *KEK_CERT_fileroute = "/home/ninjahacker/Escritorio/COMMON_CRITERIA_EAL2_cryptomodule/utils/certificate_manager/testing_cert"; // your route to cert
    int result = API_MC_Initialize_module(KEK_CERT_fileroute, cryptodata_filename);
    printf("el resultado de la inicialización del modulo es : %d\n", result);

    uint8_t key1[32], key2[32];
    API_MC_fill_buffer_random((unsigned char *)key1, 32);
    API_MC_fill_buffer_random((unsigned char *)key2, 32);

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
    API_RNG_fill_buffer_random(texto_ejemplo, sizeof(texto_ejemplo));
    unsigned char aux_buffer[sizeof(texto_ejemplo) + 72];
    unsigned char aux_buffer_2[sizeof(texto_ejemplo)];
    size_t out_length_cipher;
    size_t out_length_decipher;

    for (int i = 0; i < 20000; i++)
    {
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


    usleep(1000000);
    printf("\n");

    API_MM_Zeroize_root();
    API_MC_Shutdown_module();

    */

    GCM_ctx ctx;
    unsigned char buf[64];
    unsigned char tag_buf[16];
    int ret;

    // 32 bytes.. that's 256 bits
    const unsigned char key[32] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                                   0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
                                   0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                                   0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    unsigned char plaintext[64] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
                                   0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
                                   0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
                                   0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
                                   0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
                                   0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
                                   0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
                                   0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55};

    unsigned char expected_ciphertext[64] = {0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d,
                                             0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc,
                                             0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c,
                                             0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82,
                                             0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6,
                                             0x62, 0x89, 0x80, 0x15, 0xad};

    const unsigned char initial_value[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
                                             0xde, 0xca, 0xf8, 0x88};
    const unsigned char additional[] = {};
    unsigned char result_plaintext[64];

    API_AES_checkHWsupport();
    memset(&ctx, 0, sizeof(GCM_ctx)); // !!!!!!!!!!!!!!!!!!!!!!!!!!! importante hacer esto en el crypto.c
    // 128 bits, not bytes!
    API_AES_initkey(&(ctx.cipher_ctx), key, AES_KEY_SIZE_256); // !!!!!!!!!!!!!!!!!!!!!!!!!1 hay que inicializar la clave antes del setkey y el crypt and tag
    ret = set_gcm_key(&ctx, key, 256);

    ret = gcm_encrypt_decrypt_and_tag(&ctx, 1, 64, initial_value, 12, additional, sizeof(additional), plaintext, buf, 16, tag_buf);
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", tag_buf[i]);
    }
    putchar('\n');

    if (memcmp(buf, expected_ciphertext, 64) == 0)
    {
        printf("My local test also works\n");
    }
    else
    {
        printf("local test failed\n");
    }
    ret = gcm_authenticate_and_decrypt(&ctx, sizeof(buf), initial_value, 12, additional, sizeof(additional), tag_buf, sizeof(tag_buf), buf, result_plaintext);
    if (memcmp(plaintext, result_plaintext, 64) == 0)
    {
        printf("My local test also works decrypt\n");
    }
    else
    {
        printf("local test failed decrypt\n");
    }
    if (ret == 0)
    {
        printf("additionally the decrypted text is verified correctly\n");
    }
    else
    {
        printf("ret value = %d\n", ret);
    }

    return 0;
}