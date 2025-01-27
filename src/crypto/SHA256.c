/**
 * @file SHA256.c
 * @brief File containing all the definitions for the SHA-256 message hashing functions.
 */


/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/
#include "SHA256.h"

/****************************************************************************************************************
 * Global variables definition
 ****************************************************************************************************************/
SHA256_STRUCT SHA256_ctx;

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

void CP_sha256_computation(SHA256_STRUCT *SHA256_ctx, const SHA256_BYTE data[])
{
	_INT32 a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]); // Copy the 512bits chunk to w[0-15]
	for (; i < 64; ++i)
		m[i] = SHA256_SIG1(m[i - 2]) + m[i - 7] + SHA256_SIG0(m[i - 15]) + m[i - 16];

	a = SHA256_ctx->temp_hash[0];
	b = SHA256_ctx->temp_hash[1];
	c = SHA256_ctx->temp_hash[2];
	d = SHA256_ctx->temp_hash[3];
	e = SHA256_ctx->temp_hash[4];
	f = SHA256_ctx->temp_hash[5];
	g = SHA256_ctx->temp_hash[6];
	h = SHA256_ctx->temp_hash[7];

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

	SHA256_ctx->temp_hash[0] += a;
	SHA256_ctx->temp_hash[1] += b;
	SHA256_ctx->temp_hash[2] += c;
	SHA256_ctx->temp_hash[3] += d;
	SHA256_ctx->temp_hash[4] += e;
	SHA256_ctx->temp_hash[5] += f;
	SHA256_ctx->temp_hash[6] += g;
	SHA256_ctx->temp_hash[7] += h;
}

void CP_sha256_init(SHA256_STRUCT *SHA256_ctx)
{
	// These words were obtained by taking the first thirty-two bits of the fractional parts of the square roots of the first eight prime numbers.

	SHA256_ctx->datalen = 0;
	SHA256_ctx->bitlen = 0;
	SHA256_ctx->temp_hash[0] = 0x6a09e667;
	SHA256_ctx->temp_hash[1] = 0xbb67ae85;
	SHA256_ctx->temp_hash[2] = 0x3c6ef372;
	SHA256_ctx->temp_hash[3] = 0xa54ff53a;
	SHA256_ctx->temp_hash[4] = 0x510e527f;
	SHA256_ctx->temp_hash[5] = 0x9b05688c;
	SHA256_ctx->temp_hash[6] = 0x1f83d9ab;
	SHA256_ctx->temp_hash[7] = 0x5be0cd19;
}

void CP_sha256_update(SHA256_STRUCT *SHA256_ctx, const SHA256_BYTE data[], size_t len)
{
	_INT32 i;

	// INTRODUCE OUR DATA INTO THE 512bits CHUNK, IF THE CHUNK IS COMPLETED, WE COMPUTE IT

	for (i = 0; i < len; ++i)
	{
		SHA256_ctx->data[SHA256_ctx->datalen] = data[i];
		SHA256_ctx->datalen++;
		if (SHA256_ctx->datalen == 64)
		{
			CP_sha256_computation(SHA256_ctx, SHA256_ctx->data);
			SHA256_ctx->bitlen += 512;
			SHA256_ctx->datalen = 0;
		}
	}
}

void CP_sha256_final(SHA256_STRUCT *SHA256_ctx, SHA256_BYTE hash[])
{
	_INT32 i;

	i = SHA256_ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (SHA256_ctx->datalen < 56)
	{
		SHA256_ctx->data[i++] = 0x80;
		while (i < 56)
			SHA256_ctx->data[i++] = 0x00;
	}
	else
	{
		SHA256_ctx->data[i++] = 0x80;
		while (i < 64)
			SHA256_ctx->data[i++] = 0x00;
		CP_sha256_computation(SHA256_ctx, SHA256_ctx->data);
		memset(SHA256_ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	SHA256_ctx->bitlen += SHA256_ctx->datalen * 8;
	SHA256_ctx->data[63] = SHA256_ctx->bitlen;
	SHA256_ctx->data[62] = SHA256_ctx->bitlen >> 8;
	SHA256_ctx->data[61] = SHA256_ctx->bitlen >> 16;
	SHA256_ctx->data[60] = SHA256_ctx->bitlen >> 24;
	SHA256_ctx->data[59] = SHA256_ctx->bitlen >> 32;
	SHA256_ctx->data[58] = SHA256_ctx->bitlen >> 40;
	SHA256_ctx->data[57] = SHA256_ctx->bitlen >> 48;
	SHA256_ctx->data[56] = SHA256_ctx->bitlen >> 56;
	CP_sha256_computation(SHA256_ctx, SHA256_ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final temp_hash to the output hash.
	for (i = 0; i < 4; ++i)
	{
		hash[i] = (SHA256_ctx->temp_hash[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (SHA256_ctx->temp_hash[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (SHA256_ctx->temp_hash[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (SHA256_ctx->temp_hash[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (SHA256_ctx->temp_hash[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (SHA256_ctx->temp_hash[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (SHA256_ctx->temp_hash[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (SHA256_ctx->temp_hash[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

void API_sha256(unsigned char *msg, int length_msg ,unsigned char *out)
{
	CP_sha256_init(&SHA256_ctx);
	CP_sha256_update(&SHA256_ctx, msg, length_msg);
	CP_sha256_final(&SHA256_ctx,out);
}
