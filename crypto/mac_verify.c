/**
 * @file mac.c
 * @brief File containing all the function definitions of the HMAC and CMAC message hashing.
 */
 
 /**************************************************************************************************************** 
  * Private include files 
  ****************************************************************************************************************/
#include "mac_verify.h"

 /**************************************************************************************************************** 
  * Global variables definition 
  ****************************************************************************************************************/


 /**************************************************************************************************************** 
  * Function definition zone 
  ****************************************************************************************************************/
 
int API_verify_HMAC(unsigned char *msg, unsigned char *key, unsigned char *sign, size_t length_msg, size_t length_key, size_t length_sign)
{
	int rc = MAC_NOT_VERIFIED; // Returns value variable
	if (!msg || !key || !sign )
	{
		return rc;
	}
	if (sign == NULL || length_sign == 0)
	{ // Error when there is not signature
		return rc;
	}
	unsigned char *out ;
	out = API_CP_hmac_sha256(key, length_key, msg, length_msg);
	if (memcmp(sign, out, length_sign) != 0)// Match the HMAC signatures
		return MAC_NOT_VERIFIED;
	else
		return MAC_VERIFIED; // Returns true
}

