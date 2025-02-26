/**
 * @file crypto.c
 * @brief File containing all the functions required for the correct work of the cryptographic library interface.
 */

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/
#include "crypto.h"

/****************************************************************************************************************
 * Global variables definition
 ****************************************************************************************************************/

 AesContext aescbc_crypto_ctx;					   // AES AESCBC_CTX to store the derived AES key CSP
 AesContext aesofb_crypto_ctx;                     // AES AESOFB_CTX to store the derived AES key CSP
 GCM_ctx aesgcm_cryto_ctx;						   // AES AESGCM_CTX to store the derived AES key CSP

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/
 
/****************************************************************************************************************
 * MAC algorithms
 ****************************************************************************************************************/

int API_CP_hmac_sha256(unsigned char *msg, unsigned char *key, size_t datalen, size_t length_key, unsigned char **result)
{

	*result = API_hmac_sha256(key, length_key, msg, datalen);
	return 1;
}

int API_CP_verify_HMAC_SHA256(unsigned char *msg, unsigned char *key, unsigned char *sign, size_t length_msg, size_t length_key, size_t length_sign, uint8_t *result)
{
	*result = API_verify_HMAC(msg, key, sign, length_msg, length_key, length_sign);
	return 1; // Success
}

/****************************************************************************************************************
 * asymmetric sign algorithms
 ****************************************************************************************************************/

int API_CP_ECDSA256_sign(unsigned char p_privateKey[ECC_BYTES], unsigned char *msg, size_t msg_length, unsigned char p_signature[ECC_BYTES * 2])
{
	unsigned char hash[32];
	API_sha256(msg, msg_length, hash);
	ecdsa_sign(p_privateKey, hash, p_signature);
	return 1;
}
/*
 * Verify the ECDSA P-256 sign sent by the receiver and give the result
 */
int API_CP_verify_ECDSA256(unsigned char *pubkey, unsigned char *msg, unsigned char *sign, size_t length_pukey, size_t msg_length, size_t length_sign, uint8_t *result)
{
	unsigned char hash[32];
	API_sha256(msg, msg_length, hash);
	*result = API_ecdsa_verify(pubkey, hash, sign);

	return 1; // Success
}

/****************************************************************************************************************
 * hashing algorithms
 ****************************************************************************************************************/

/*
 * Generates the SHA hash for the message with the SHA mode indicated
 */
int API_CP_sha256(unsigned char *msg, size_t length_msg, unsigned char *sha_out)
{
	API_sha256(msg, length_msg, sha_out);
	return 1; // Success
}
/*
 * Cyclic redundancy check functions
 */
int API_CP_crc(unsigned char *msg, size_t lenght_msg, CRC type_crc, unsigned int *CRC_out)
{
	switch (type_crc)
	{
	case crc16:
		*CRC_out = crc_16(msg, lenght_msg);
		break;
	case crc24:
		*CRC_out = crc_24(msg, lenght_msg);
		break;
	case crc32:
		*CRC_out = crc_32(msg, lenght_msg);
		break;
	default:
		break;
		// error
	}
	return 1; // Success
}

/****************************************************************************************************************
 * ciphers algorithms
 ****************************************************************************************************************/

/*
 * AES_CBC with padding
 */
int API_CP_AESCBC_encrypt(unsigned char *plaintext, size_t *len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *ciphertext)
{
	API_AES_initkey(&aescbc_crypto_ctx,key,AES_KEY_SIZE);
	// updates length if padding is required
	CP_addPaddingAes(plaintext, len, plaintext);
	// just encrypt with CBC mode
	API_AESCBC_encrypt(aescbc_crypto_ctx,plaintext, *len, iv, ciphertext);

	return 1;
}

int API_CP_AESCBC_decrypt(unsigned char *ciphertext, size_t *len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *plaintext)
{
	API_AES_initkey(&aescbc_crypto_ctx,key,AES_KEY_SIZE);
	API_AESCBC_decrypt(aescbc_crypto_ctx,ciphertext, *len, iv, plaintext);

	int padding = CP_getPaddingLength(plaintext, *len);

	if (padding != -1)
		*len -= padding;

	return 1;
}

/*
 * AES_OFB with padding
 */
int API_CP_AESOFB_encryptdecrypt(unsigned char *input, size_t in_len, unsigned char *key, unsigned int AES_KEY_SIZE, unsigned char *iv, unsigned char *output){
	API_AES_initkey(&aesofb_crypto_ctx,key,AES_KEY_SIZE);
	API_AES_OFB_EncryptDecrypt(aesofb_crypto_ctx,input,in_len,iv,output);
	return 1;
}

/****************************************************************************************************************
 * AEAD algorithms
 ****************************************************************************************************************/

 int API_CP_AEAD_AESGCM_encrypt_sign(unsigned char *plaintext, size_t plaintext_len,unsigned char *associated_data, size_t associated_data_len,size_t tag_len,unsigned char *key,
									 unsigned int AES_KEY_SIZE,unsigned char *iv, unsigned int iv_len,unsigned char *ciphertext,unsigned char *tag)
{
	memset(&aesgcm_cryto_ctx, 0, sizeof(GCM_ctx));
	//initialize round keys for aes_gcm
	API_AES_initkey(&(aesgcm_cryto_ctx.cipher_ctx), key, AES_KEY_SIZE_256);
	set_gcm_key(&aesgcm_cryto_ctx, key, AES_KEY_SIZE_256 * 8);
	gcm_encrypt_decrypt_and_tag(&aesgcm_cryto_ctx,1,plaintext_len,iv,iv_len,associated_data,associated_data_len,plaintext,ciphertext,tag_len,tag);
	return 1;
}

 int API_CP_AEAD_AESGCM_verify_decrypt(unsigned char *ciphertext,size_t ciphertext_len,unsigned char *associated_data, size_t associated_data_len,size_t tag_len,unsigned char *key,
									   unsigned int AES_KEY_SIZE,unsigned char *iv, unsigned int iv_len,unsigned char *plaintext,unsigned char *tag,uint8_t *verify)
{
	int ret;
	int tag_mismatch = 0;
	unsigned char computed_tag[16]; // Buffer to store the computed authentication tag.
	memset(&aesgcm_cryto_ctx, 0, sizeof(GCM_ctx));
	//initialize round keys for aes_gcm
	API_AES_initkey(&(aesgcm_cryto_ctx.cipher_ctx), key, AES_KEY_SIZE_256);
	set_gcm_key(&aesgcm_cryto_ctx, key, AES_KEY_SIZE_256 * 8);

	if(ret = gcm_encrypt_decrypt_and_tag(&aesgcm_cryto_ctx,2,ciphertext_len,iv,iv_len,associated_data,associated_data_len,ciphertext,plaintext,tag_len,computed_tag) != 0){
		return ret;
	}

	// Verify the computed tag against the expected tag in constant time.
    for (int i = 0; i < tag_len; i++)
    {
        tag_mismatch |= tag[i] ^ computed_tag[i];
    }

    // If the tags do not match, return an error.
    if (tag_mismatch != 0)
    {
		*verify = -1;
        return -1; // Error: authentication tag mismatch.
    }
	*verify = 1;
    return 0; // Success.

 }