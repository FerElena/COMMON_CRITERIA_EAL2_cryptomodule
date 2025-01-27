/**
 * @file module_initialization.c
 * @brief Implementation of the memory tracking and cryptographic module initialization.
 */

#include "module_initialization.h"

// Tracker indexs for memory tracking
int TI_FS_cipher_key;
int TI_FS_data_buffer;
int TI_PCA_data_buffer_sed;
int TI_Current_Key_In_Use;
int TI_AES_CBC_ctx;
int TI_AESOFB_CTX;
int TI_AESOFB_outputBlock;
int TI_AESOFB_ivEnc;
int TI_ECDSA_curve_p;
int TI_ECDSA_curve_B;
int TI_ECDSA_curve_G;
int TI_ECDSA_curve_n;
int TI_ECDSA_k;
int TI_ECDSA_l_tmp;
int TI_ECDSA_l_s;
int TI_HMAC256_ihash;
int TI_HMAC256_ohash;
int TI_HMAC256_k;
int TI_HMAC256_k_ipad;
int TI_HMAC256_k_opad;
int TI_HMAC256_sha256_struct;
int TI_SHA256_ctx;


int Memory_tracking_initialization()
{
    uint8_t correct_tracker_init_result[64];
    uint32_t counter = 0;

    // Initialize array with 1s to indicate success by default
    for (int i = 0; i < sizeof(correct_tracker_init_result) / sizeof(correct_tracker_init_result[0]); correct_tracker_init_result[i++] = 1)
        ;

    // Initialize the memory tracker pointers
    API_MT_initialize_trackers();

    // Register each cryptographic component with the memory tracker system
    TI_FS_cipher_key = API_MT_add_tracker(FS_cipher_key, sizeof(FS_cipher_key), CSP); // FS cipher key
    correct_tracker_init_result[counter++] = (TI_FS_cipher_key >= 0) ? 1 : 0;

    TI_FS_data_buffer = API_MT_add_tracker(FS_data_buffer, sizeof(FS_data_buffer), CSP); // FS auxiliary buffer
    correct_tracker_init_result[counter++] = (TI_FS_data_buffer >= 0) ? 1 : 0;

    TI_PCA_data_buffer_sed = API_MT_add_tracker(PCA_data_buffer_sed, sizeof(PCA_data_buffer_sed), CSP); // Packet cipher and auth buffer
    correct_tracker_init_result[counter++] = (TI_PCA_data_buffer_sed >= 0) ? 1 : 0;

    TI_Current_Key_In_Use = API_MT_add_tracker(&Current_key_in_use, sizeof(Current_key_in_use), CSP); // Packet cipher and auth auxiliary buffer
    correct_tracker_init_result[counter++] = (TI_Current_Key_In_Use >= 0) ? 1 : 0;

    TI_AES_CBC_ctx = API_MT_add_tracker(&AES_CBC_ctx, sizeof(AES_CBC_ctx), CSP); // AES-CBC context
    correct_tracker_init_result[counter++] = (TI_AES_CBC_ctx >= 0) ? 1 : 0;

    TI_AESOFB_CTX = API_MT_add_tracker(&AESOFB_CTX, sizeof(AESOFB_CTX), CSP); // AES-OFB context
    correct_tracker_init_result[counter++] = (TI_AESOFB_CTX >= 0) ? 1 : 0;

    TI_AESOFB_outputBlock = API_MT_add_tracker(&AESOFB_outputBlock, sizeof(AESOFB_outputBlock), CSP); // AES-OFB output block
    correct_tracker_init_result[counter++] = (TI_AESOFB_outputBlock >= 0) ? 1 : 0;

    TI_AESOFB_ivEnc = API_MT_add_tracker(&AESOFB_ivEnc, sizeof(AESOFB_ivEnc), CSP); // AES-OFB encrypted IV
    correct_tracker_init_result[counter++] = (TI_AESOFB_ivEnc >= 0) ? 1 : 0;

    TI_ECDSA_curve_p = API_MT_add_tracker(ECDSA_curve_p, sizeof(ECDSA_curve_p), CSP); // ECDSA curve parameter p
    correct_tracker_init_result[counter++] = (TI_ECDSA_curve_p >= 0) ? 1 : 0;

    TI_ECDSA_curve_B = API_MT_add_tracker(ECDSA_curve_b, sizeof(ECDSA_curve_b), CSP); // ECDSA curve parameter B
    correct_tracker_init_result[counter++] = (TI_ECDSA_curve_B >= 0) ? 1 : 0;

    TI_ECDSA_curve_G = API_MT_add_tracker(&ECDSA_curve_G, sizeof(ECDSA_curve_G), CSP); // ECDSA generator point G
    correct_tracker_init_result[counter++] = (TI_ECDSA_curve_G >= 0) ? 1 : 0;

    TI_ECDSA_curve_n = API_MT_add_tracker(ECDSA_curve_n, sizeof(ECDSA_curve_n), CSP); // ECDSA curve order n
    correct_tracker_init_result[counter++] = (TI_ECDSA_curve_n >= 0) ? 1 : 0;

    TI_ECDSA_k = API_MT_add_tracker(ECDSA_k, sizeof(ECDSA_k), CSP); // ECDSA ephemeral key k
    correct_tracker_init_result[counter++] = (TI_ECDSA_k >= 0) ? 1 : 0;

    TI_ECDSA_l_tmp = API_MT_add_tracker(ECDSA_l_tmp, sizeof(ECDSA_l_tmp), CSP); // ECDSA temporary value
    correct_tracker_init_result[counter++] = (TI_ECDSA_l_tmp >= 0) ? 1 : 0;

    TI_ECDSA_l_s = API_MT_add_tracker(ECDSA_l_s, sizeof(ECDSA_l_s), CSP); // ECDSA signature value
    correct_tracker_init_result[counter++] = (TI_ECDSA_l_s >= 0) ? 1 : 0;

    TI_HMAC256_ihash = API_MT_add_tracker(HMAC256_ihash, sizeof(HMAC256_ihash), CSP); // HMAC-SHA256 inner hash
    correct_tracker_init_result[counter++] = (TI_HMAC256_ihash >= 0) ? 1 : 0;

    TI_HMAC256_ohash = API_MT_add_tracker(HMAC256_ohash, sizeof(HMAC256_ohash), CSP); // HMAC-SHA256 outer hash
    correct_tracker_init_result[counter++] = (TI_HMAC256_ohash >= 0) ? 1 : 0;

    TI_HMAC256_k = API_MT_add_tracker(HMAC256_k, sizeof(HMAC256_k), CSP); // HMAC-SHA256 secret key
    correct_tracker_init_result[counter++] = (TI_HMAC256_k >= 0) ? 1 : 0;

    TI_HMAC256_k_ipad = API_MT_add_tracker(HMAC256_k_ipad, sizeof(HMAC256_k_ipad), CSP); // HMAC-SHA256 inner padding
    correct_tracker_init_result[counter++] = (TI_HMAC256_k_ipad >= 0) ? 1 : 0;

    TI_HMAC256_k_opad = API_MT_add_tracker(HMAC256_k_opad, sizeof(HMAC256_k_opad), CSP); // HMAC-SHA256 outer padding
    correct_tracker_init_result[counter++] = (TI_HMAC256_k_opad >= 0) ? 1 : 0;

    TI_HMAC256_sha256_struct = API_MT_add_tracker(&HMAC256_sha256_struct, sizeof(HMAC256_sha256_struct), CSP); // HMAC-SHA256 context
    correct_tracker_init_result[counter++] = (TI_HMAC256_sha256_struct >= 0) ? 1 : 0;

    TI_SHA256_ctx = API_MT_add_tracker(&SHA256_ctx, sizeof(SHA256_ctx), CSP); // SHA-256 context
    correct_tracker_init_result[counter++] = (TI_SHA256_ctx >= 0) ? 1 : 0;

    for (int i = 0; i < sizeof(correct_tracker_init_result); i++)
    { // check for errors
        if (correct_tracker_init_result[i] == 0)
        {
            return INIT_INCORRECT_TRACKER_INIT;
        }
    }
    return CORRECT_TRACKER_INIT; // everything ok
}

int File_system_first_initialization(unsigned char *KEK_CERTIFICATE_file, unsigned char *Cryptodata_filename)
{
    uint8_t key_AES256_certificate[129]; // Buffer to store the AES-256 key[32 bytes], the ECDSA signature[64 bytes] , and the ECDSA PUB KEY [33 bytes compressed]
    FILE *file = NULL;

    // Check if the provided key file path is valid.
    if (KEK_CERTIFICATE_file == NULL)
    {
        return INIT_INCORRECT_KEYFILE_PATH;
    }
    if (Cryptodata_filename == NULL)
    {
        return INIT_INCORRECT_FILESYSTEM_INIT;
    }

    // Try to open the key file in read-binary mode.
    file = fopen(KEK_CERTIFICATE_file, "rb");
    if (file == NULL)
    {
        return INIT_INCORRECT_KEYFILE_PATH; // Return if file can't be opened.
    }

    // Read the AES-256 key from the file.
    size_t bytes_read = fread(key_AES256_certificate, 1, 129, file);
    if (bytes_read < 129)
    {
        if (feof(file))
        {
            return INIT_INCORRECT_KEYFILE_FORMAT; // Key file is too short.
        }
        fclose(file);                  // Ensure file is closed before returning.
        return INIT_INCORRECT_KEYFILE_READ; // Error reading key.
    }
    fclose(file); // Close the key file after reading.

    // Initialize the file system in 'init' mode for first-time setup.
    if (API_FS_initiate_file_system(MODE_INIT, Cryptodata_filename, strlen(Cryptodata_filename)) < 0)
    {
        return INIT_INCORRECT_FILESYSTEM_INIT; // File system initialization failed.
    }

    // Set up AES encryption with the loaded key.
    API_FS_setup_cipher(CIPHER_ON, key_AES256_certificate);

    // Update the memory tracker with the new key.
    API_MT_update_tracker(&trackers[TI_FS_cipher_key]);

    uint8_t previus_state = PREVIUS_NORMAL_STATE;
    int result1 = API_FS_create_file_data(CONF_FILENAME, strlen(CONF_FILENAME), &previus_state, 1, NOT_CSP);

    int result2 = API_FS_create_file_data(CERT_FILENAME, strlen(CERT_FILENAME), key_AES256_certificate + 32, sizeof(key_AES256_certificate) - 32, CSP); // store the 97 bytes of sign and pubkey of ecdsa

    unsigned char Schneier_patterns[] = {0x00, 0xFF, 0xAA, 0x55, 0xAA, 0x55}; // zeroize old memory space for key
    for (int i = 0; i < 6; i++)
    {
        for (int j = 0; j < 32; j++)
        {
            key_AES256_certificate[i] = Schneier_patterns[j];
        }
    }
    if (result1 != FILESYSTEM_OK && result2 != FILESYSTEM_OK)
    {
        return INIT_INCORRECT_FILESYSTEM_INIT;
    }
    return CORRECT_FILESYSTEM_INIT; // Return success.
}

int File_system_normal_initialization(unsigned char *KEK_CERTIFICATE_file, unsigned char *Cryptodata_filename)
{
    uint8_t key_AES256[32]; // Buffer to store the AES-256 key.
    FILE *file = NULL;

    // Check if the provided key file path is valid.
    if (KEK_CERTIFICATE_file == NULL)
    {
        return INIT_INCORRECT_KEYFILE_PATH;
    }

    // Try to open the key file in read-binary mode.
    file = fopen(KEK_CERTIFICATE_file, "rb");
    if (file == NULL)
    {
        return INIT_INCORRECT_KEYFILE_PATH; // Return if file can't be opened.
    }

    // Read the AES-256 key from the file.
    size_t bytes_read = fread(key_AES256, 1, AES_KEY_SIZE_256, file);
    if (bytes_read < AES_KEY_SIZE_256)
    {
        if (feof(file))
        {
            return INIT_INCORRECT_KEYFILE_FORMAT; // Key file is too short.
        }
        fclose(file);                  // Ensure file is closed before returning.
        return INIT_INCORRECT_KEYFILE_READ; // Error reading key.
    }
    fclose(file); // Close the key file after reading.

    // Initialize the file system in 'load' mode for normal operation.
    if (API_FS_initiate_file_system(MODE_LOAD, Cryptodata_filename, strlen(Cryptodata_filename)) < 0)
    {
        return INIT_INCORRECT_FILESYSTEM_INIT; // File system initialization failed.
    }
    //Check for previus error states in the cryptomodule
    uint8_t *previus_state;
    uint32_t config_size;
    int result = API_FS_read_file_data(CONF_FILENAME,strlen(CONF_FILENAME),&previus_state,&config_size);
    if(*previus_state == PREVIUS_ERROR_STATE || result != FILESYSTEM_OK){
        return INIT_PREVIUS_ERROR_STATE;
    }

    // Set up AES encryption with the loaded key.
    result = API_FS_setup_cipher(CIPHER_ON, key_AES256);
    if(result == 0){
        return INIT_INCORRECT_FILESYSTEM_INIT;
    }

    // Update the memory tracker with the new key.
    API_MT_update_tracker(&trackers[TI_FS_cipher_key]);

    unsigned char Schneier_patterns[] = {0x00, 0xFF, 0xAA, 0x55, 0xAA, 0x55}; // zeroize old memory space for key
    for (int i = 0; i < 6; i++)
    {
        for (int j = 0; j < 32; j++)
        {
            key_AES256[i] = Schneier_patterns[j];
        }
    }

    return CORRECT_FILESYSTEM_INIT; // Return success.
}

int file_exists(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file)
    {
        fclose(file);
        return 1; // El archivo existe
    }
    return 0; // El archivo no existe
}

int API_INIT_initialize_module(unsigned char *KEK_CERTIFICATE_file, unsigned char *Cryptodata_filename)
{
    if(API_SM_get_current_state() != STATE_INITIALIZATION){
        API_SM_State_Change(SM_ERROR);
        return SM_ERROR_STATE;
    }
    int return_value;
    int result1 = Memory_tracking_initialization(); // Initialize memory tracking
    // Check if memory tracking initialized correctly
    if (result1 != CORRECT_TRACKER_INIT)
    {
        return result1; // Return error code if initialization failed
    }

    // Check if the cryptodata file exists
    if (file_exists(Cryptodata_filename))
    {
        // Perform normal file system initialization
        result1 = File_system_normal_initialization(KEK_CERTIFICATE_file, Cryptodata_filename);
        // Check if the normal initialization was successful
        if (result1 != CORRECT_FILESYSTEM_INIT)
        {
            return result1; // Return error code if initialization failed
        }
        return_value = INITIALIZE_OK_NORMAL_INIT;
    }
    else
    {
        // Perform first-time file system initialization
        result1 = File_system_first_initialization(KEK_CERTIFICATE_file, Cryptodata_filename);
        // Check if the first-time initialization was successful
        if (result1 != CORRECT_FILESYSTEM_INIT)
        {
            return result1; // Return error code if initialization failed
        }
        return_value = INITIALIZE_OK_FIRST_INIT;
    }
    result1 = API_LT_startTraceFile();
        if (result1 == LT_TRACER_ERROR)
        {
            return INIT_TRACER_INIT_ERROR;  // Return error code if tracer could not be initialized
        }
        
    return return_value; // Return success code if all initializations succeeded
}
