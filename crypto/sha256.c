/**
 * @file sha256.c
 * @brief File containing all the definitions for the SHA message hashing functions.
 */


/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/
#include "sha256.h"

/****************************************************************************************************************
 * Global variables definition
 ****************************************************************************************************************/

// These 0 1 63 words represent the first thirty-two bits of the fractional parts of the cube roots of the first sixtyfour prime numbers.

static const _INT32 k256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};



/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

void CP_sha256_computation(SHA256_STRUCT *sha256_struct, const SHA256_BYTE data[])
{
	_INT32 a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]); // Copy the 512bits chunk to w[0-15]
	for (; i < 64; ++i)
		m[i] = SHA256_SIG1(m[i - 2]) + m[i - 7] + SHA256_SIG0(m[i - 15]) + m[i - 16];

	a = sha256_struct->temp_hash[0];
	b = sha256_struct->temp_hash[1];
	c = sha256_struct->temp_hash[2];
	d = sha256_struct->temp_hash[3];
	e = sha256_struct->temp_hash[4];
	f = sha256_struct->temp_hash[5];
	g = sha256_struct->temp_hash[6];
	h = sha256_struct->temp_hash[7];

	for (i = 0; i < 64; ++i)
	{
		t1 = h + SHA256_EP1(e) + SHA256_CH(e, f, g) + k256[i] + m[i];
		t2 = SHA256_EP0(a) + SHA256_MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	sha256_struct->temp_hash[0] += a;
	sha256_struct->temp_hash[1] += b;
	sha256_struct->temp_hash[2] += c;
	sha256_struct->temp_hash[3] += d;
	sha256_struct->temp_hash[4] += e;
	sha256_struct->temp_hash[5] += f;
	sha256_struct->temp_hash[6] += g;
	sha256_struct->temp_hash[7] += h;
}

void CP_sha256_init(SHA256_STRUCT *sha256_struct)
{
	// These words were obtained by taking the first thirty-two bits of the fractional parts of the square roots of the first eight prime numbers.

	sha256_struct->datalen = 0;
	sha256_struct->bitlen = 0;
	sha256_struct->temp_hash[0] = 0x6a09e667;
	sha256_struct->temp_hash[1] = 0xbb67ae85;
	sha256_struct->temp_hash[2] = 0x3c6ef372;
	sha256_struct->temp_hash[3] = 0xa54ff53a;
	sha256_struct->temp_hash[4] = 0x510e527f;
	sha256_struct->temp_hash[5] = 0x9b05688c;
	sha256_struct->temp_hash[6] = 0x1f83d9ab;
	sha256_struct->temp_hash[7] = 0x5be0cd19;
}

void CP_sha256_update(SHA256_STRUCT *sha256_struct, const SHA256_BYTE data[], size_t len)
{
	_INT32 i;

	// INTRODUCE OUR DATA INTO THE 512bits CHUNK, IF THE CHUNK IS COMPLETED, WE COMPUTE IT

	for (i = 0; i < len; ++i)
	{
		sha256_struct->data[sha256_struct->datalen] = data[i];
		sha256_struct->datalen++;
		if (sha256_struct->datalen == 64)
		{
			CP_sha256_computation(sha256_struct, sha256_struct->data);
			sha256_struct->bitlen += 512;
			sha256_struct->datalen = 0;
		}
	}
}

void CP_sha256_final(SHA256_STRUCT *sha256_struct, SHA256_BYTE hash[])
{
	_INT32 i;

	i = sha256_struct->datalen;

	// Pad whatever data is left in the buffer.
	if (sha256_struct->datalen < 56)
	{
		sha256_struct->data[i++] = 0x80;
		while (i < 56)
			sha256_struct->data[i++] = 0x00;
	}
	else
	{
		sha256_struct->data[i++] = 0x80;
		while (i < 64)
			sha256_struct->data[i++] = 0x00;
		CP_sha256_computation(sha256_struct, sha256_struct->data);
		memset(sha256_struct->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	sha256_struct->bitlen += sha256_struct->datalen * 8;
	sha256_struct->data[63] = sha256_struct->bitlen;
	sha256_struct->data[62] = sha256_struct->bitlen >> 8;
	sha256_struct->data[61] = sha256_struct->bitlen >> 16;
	sha256_struct->data[60] = sha256_struct->bitlen >> 24;
	sha256_struct->data[59] = sha256_struct->bitlen >> 32;
	sha256_struct->data[58] = sha256_struct->bitlen >> 40;
	sha256_struct->data[57] = sha256_struct->bitlen >> 48;
	sha256_struct->data[56] = sha256_struct->bitlen >> 56;
	CP_sha256_computation(sha256_struct, sha256_struct->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final temp_hash to the output hash.
	for (i = 0; i < 4; ++i)
	{
		hash[i] = (sha256_struct->temp_hash[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (sha256_struct->temp_hash[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (sha256_struct->temp_hash[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (sha256_struct->temp_hash[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (sha256_struct->temp_hash[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (sha256_struct->temp_hash[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (sha256_struct->temp_hash[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (sha256_struct->temp_hash[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

void API_sha256(unsigned char *msg, int length_msg ,unsigned char *out)
{
	SHA256_STRUCT sha256_struct; // CHECKEAR SI ES NECESARIO ZEROIZAR LO DE DENTRO DE ESTA ESTRUCTURA

	CP_sha256_init(&sha256_struct);
	CP_sha256_update(&sha256_struct, msg, length_msg);
	CP_sha256_final(&sha256_struct,out);
}
