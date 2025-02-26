#include "AES_GCM.h"

#define EXTRACT_UINT32_BE(var, buf, idx)                                                                                                                \
    {                                                                                                                                                   \
        (var) = ((uint32_t)(buf)[(idx)] << 24) | ((uint32_t)(buf)[(idx) + 1] << 16) | ((uint32_t)(buf)[(idx) + 2] << 8) | ((uint32_t)(buf)[(idx) + 3]); \
    }

#define INSERT_UINT32_BE(var, buf, idx)                  \
    {                                                    \
        (buf)[(idx)] = (unsigned char)((var) >> 24);     \
        (buf)[(idx) + 1] = (unsigned char)((var) >> 16); \
        (buf)[(idx) + 2] = (unsigned char)((var) >> 8);  \
        (buf)[(idx) + 3] = (unsigned char)((var));       \
    }

int generate_gcm_table(GCM_ctx *context)
{
    int i, j;
    uint64_t high_part, low_part;
    uint64_t val_high, val_low;
    unsigned char hash_block[16];
    unsigned char zero_block[16];

    memset(zero_block, 0, 16);
    API_AES_encrypt_block(&(context->cipher_ctx), zero_block, hash_block); // Ensure cipher context is initialized with the key first!

    /* Extract 128-bit value as two 64-bit integers, big-endian format */
    EXTRACT_UINT32_BE(high_part, hash_block, 0);
    EXTRACT_UINT32_BE(low_part, hash_block, 4);
    val_high = ((uint64_t)high_part << 32) | low_part;

    EXTRACT_UINT32_BE(high_part, hash_block, 8);
    EXTRACT_UINT32_BE(low_part, hash_block, 12);
    val_low = ((uint64_t)high_part << 32) | low_part;

    /* Position 8 (1000 in binary) corresponds to 1 in GF(2^128) */
    context->HL[8] = val_low;
    context->HH[8] = val_high;

    /* If AES-NI hardware acceleration is available, skip table generation */
    if (API_AES_checkHWsupport() == hardware_AES_NI)
        return 0;

    /* Position 0 corresponds to 0 in GF(2^128) */
    context->HH[0] = 0;
    context->HL[0] = 0;

    for (i = 4; i > 0; i >>= 1)
    {
        uint32_t tmp = (val_low & 1) * 0xe1000000U;
        val_low = (val_high << 63) | (val_low >> 1);
        val_high = (val_high >> 1) ^ ((uint64_t)tmp << 32);

        context->HL[i] = val_low;
        context->HH[i] = val_high;
    }

    for (i = 2; i <= 8; i *= 2)
    {
        uint64_t *high_table = context->HH + i;
        uint64_t *low_table = context->HL + i;
        val_high = *high_table;
        val_low = *low_table;
        for (j = 1; j < i; j++)
        {
            high_table[j] = val_high ^ context->HH[j];
            low_table[j] = val_low ^ context->HL[j];
        }
    }

    return 0;
}

int set_gcm_key(GCM_ctx *context, const unsigned char *key, unsigned int key_bits)
{
    int result;

    if ((result = generate_gcm_table(context)) != 0)
        return result;

    return 0;
}

/*
 * Shoup's method for multiplication use this table with
 *      gf128_mult_table_last4[x] = x times P^128
 * where x and gf128_mult_table_last4[x] are seen as elements of GF(2^128) as in [MGV]
 */
static const uint64_t gf128_mult_table_last4[16] =
    {
        0x0000, 0x1c20, 0x3840, 0x2460,
        0x7080, 0x6ca0, 0x48c0, 0x54e0,
        0xe100, 0xfd20, 0xd940, 0xc560,
        0x9180, 0x8da0, 0xa9c0, 0xb5e0};

// Define PCLMULQDQ instruction as a byte sequence for inline assembly
#define PCLMULQDQ ".byte 0x66,0x0F,0x3A,0x44,"

// Define PCLMULQDQ instruction as a byte sequence for inline assembly
#define PCLMULQDQ ".byte 0x66,0x0F,0x3A,0x44,"

// Define operand combinations for PCLMULQDQ instruction
#define XMM0_XMM0 "0xC0" // xmm0 * xmm0
#define XMM0_XMM1 "0xC8" // xmm0 * xmm1
#define XMM0_XMM2 "0xD0" // xmm0 * xmm2
#define XMM0_XMM3 "0xD8" // xmm0 * xmm3
#define XMM0_XMM4 "0xE0" // xmm0 * xmm4
#define XMM1_XMM0 "0xC1" // xmm1 * xmm0
#define XMM1_XMM2 "0xD1" // xmm1 * xmm2

/**
 * Performs GCM (Galois/Counter Mode) multiplication using AES-NI and PCLMULQDQ instructions.
 * This function multiplies two 128-bit operands in the finite field GF(2^128) modulo the
 * GCM polynomial x^128 + x^7 + x^2 + x + 1.
 *
 * @param result          Output buffer to store the result (16 bytes).
 * @param operand_a       First input operand (16 bytes).
 * @param operand_b       Second input operand (16 bytes).
 */
void aesni_gcm_multiply(unsigned char result[16], const unsigned char operand_a[16], const unsigned char operand_b[16])
{
    unsigned char reversed_a[16], reversed_b[16], reversed_result[16];
    size_t index;

    /**
     * Reverse the byte order of the input operands.
     * This is necessary because the inputs are in big-endian format, but the
     * PCLMULQDQ instruction expects little-endian format.
     */
    for (index = 0; index < 16; index++)
    {
        reversed_a[index] = operand_a[15 - index]; // Reverse operand_a
        reversed_b[index] = operand_b[15 - index]; // Reverse operand_b
    }

    /**
     * Inline assembly block to perform the GCM multiplication.
     * This block uses the PCLMULQDQ instruction to perform carryless multiplication
     * and reduces the result modulo the GCM polynomial.
     */
    asm(
        "movdqu (%0), %%xmm0               \n\t" /** Load reversed_a into xmm0 (a1:a0). */
        "movdqu (%1), %%xmm1               \n\t" /** Load reversed_b into xmm1 (b1:b0). */

        /**
         * Perform carryless multiplication of xmm0 and xmm1 using the [CLMUL-WP] algorithm.
         * The result is stored in xmm2:xmm1.
         */
        "movdqa %%xmm1, %%xmm2             \n\t" /** Copy b1:b0 to xmm2. */
        "movdqa %%xmm1, %%xmm3             \n\t" /** Copy b1:b0 to xmm3. */
        "movdqa %%xmm1, %%xmm4             \n\t" /** Copy b1:b0 to xmm4. */
        PCLMULQDQ XMM0_XMM1 ",0x00         \n\t" /** Compute a0 * b0 = c1:c0. */
        PCLMULQDQ XMM0_XMM2 ",0x11         \n\t" /** Compute a1 * b1 = d1:d0. */
        PCLMULQDQ XMM0_XMM3 ",0x10         \n\t" /** Compute a0 * b1 = e1:e0. */
        PCLMULQDQ XMM0_XMM4 ",0x01         \n\t" /** Compute a1 * b0 = f1:f0. */
        "pxor %%xmm3, %%xmm4               \n\t" /** XOR e1:e0 and f1:f0. */
        "movdqa %%xmm4, %%xmm3             \n\t" /** Copy result to xmm3. */
        "psrldq $8, %%xmm4                 \n\t" /** Shift right by 8 bytes. */
        "pslldq $8, %%xmm3                 \n\t" /** Shift left by 8 bytes. */
        "pxor %%xmm4, %%xmm2               \n\t" /** XOR with d1:d0. */
        "pxor %%xmm3, %%xmm1               \n\t" /** XOR with c1:c0. */

        /**
         * Shift the result one bit to the left.
         * This is part of the reduction process and uses [CLMUL-WP] equation 27.
         */
        "movdqa %%xmm1, %%xmm3             \n\t" /** Copy xmm1 to xmm3. */
        "movdqa %%xmm2, %%xmm4             \n\t" /** Copy xmm2 to xmm4. */
        "psllq $1, %%xmm1                  \n\t" /** Shift xmm1 left by 1 bit. */
        "psllq $1, %%xmm2                  \n\t" /** Shift xmm2 left by 1 bit. */
        "psrlq $63, %%xmm3                 \n\t" /** Shift xmm3 right by 63 bits. */
        "psrlq $63, %%xmm4                 \n\t" /** Shift xmm4 right by 63 bits. */
        "movdqa %%xmm3, %%xmm5             \n\t" /** Copy xmm3 to xmm5. */
        "pslldq $8, %%xmm3                 \n\t" /** Shift xmm3 left by 8 bytes. */
        "pslldq $8, %%xmm4                 \n\t" /** Shift xmm4 left by 8 bytes. */
        "psrldq $8, %%xmm5                 \n\t" /** Shift xmm5 right by 8 bytes. */
        "por %%xmm3, %%xmm1                \n\t" /** OR xmm1 with xmm3. */
        "por %%xmm4, %%xmm2                \n\t" /** OR xmm2 with xmm4. */
        "por %%xmm5, %%xmm2                \n\t" /** OR xmm2 with xmm5. */

        /**
         * Reduce the result modulo the GCM polynomial x^128 + x^7 + x^2 + x + 1.
         * This uses [CLMUL-WP] algorithm 5.
         */
        /* Step 2 (1) */
        "movdqa %%xmm1, %%xmm3             \n\t" /** Copy xmm1 to xmm3. */
        "movdqa %%xmm1, %%xmm4             \n\t" /** Copy xmm1 to xmm4. */
        "movdqa %%xmm1, %%xmm5             \n\t" /** Copy xmm1 to xmm5. */
        "psllq $63, %%xmm3                 \n\t" /** Shift xmm3 left by 63 bits. */
        "psllq $62, %%xmm4                 \n\t" /** Shift xmm4 left by 62 bits. */
        "psllq $57, %%xmm5                 \n\t" /** Shift xmm5 left by 57 bits. */

        /* Step 2 (2) */
        "pxor %%xmm4, %%xmm3               \n\t" /** XOR xmm3 with xmm4. */
        "pxor %%xmm5, %%xmm3               \n\t" /** XOR xmm3 with xmm5. */
        "pslldq $8, %%xmm3                 \n\t" /** Shift xmm3 left by 8 bytes. */
        "pxor %%xmm3, %%xmm1               \n\t" /** XOR xmm1 with xmm3. */

        /* Steps 3 and 4 */
        "movdqa %%xmm1, %%xmm0             \n\t" /** Copy xmm1 to xmm0. */
        "movdqa %%xmm1, %%xmm4             \n\t" /** Copy xmm1 to xmm4. */
        "movdqa %%xmm1, %%xmm5             \n\t" /** Copy xmm1 to xmm5. */
        "psrlq $1, %%xmm0                  \n\t" /** Shift xmm0 right by 1 bit. */
        "psrlq $2, %%xmm4                  \n\t" /** Shift xmm4 right by 2 bits. */
        "psrlq $7, %%xmm5                  \n\t" /** Shift xmm5 right by 7 bits. */
        "pxor %%xmm4, %%xmm0               \n\t" /** XOR xmm0 with xmm4. */
        "pxor %%xmm5, %%xmm0               \n\t" /** XOR xmm0 with xmm5. */
        "movdqa %%xmm1, %%xmm3             \n\t" /** Copy xmm1 to xmm3. */
        "movdqa %%xmm1, %%xmm4             \n\t" /** Copy xmm1 to xmm4. */
        "movdqa %%xmm1, %%xmm5             \n\t" /** Copy xmm1 to xmm5. */
        "psllq $63, %%xmm3                 \n\t" /** Shift xmm3 left by 63 bits. */
        "psllq $62, %%xmm4                 \n\t" /** Shift xmm4 left by 62 bits. */
        "psllq $57, %%xmm5                 \n\t" /** Shift xmm5 left by 57 bits. */
        "pxor %%xmm4, %%xmm3               \n\t" /** XOR xmm3 with xmm4. */
        "pxor %%xmm5, %%xmm3               \n\t" /** XOR xmm3 with xmm5. */
        "psrldq $8, %%xmm3                 \n\t" /** Shift xmm3 right by 8 bytes. */
        "pxor %%xmm3, %%xmm0               \n\t" /** XOR xmm0 with xmm3. */
        "pxor %%xmm1, %%xmm0               \n\t" /** XOR xmm0 with xmm1. */
        "pxor %%xmm2, %%xmm0               \n\t" /** XOR xmm0 with xmm2. */

        "movdqu %%xmm0, (%2)               \n\t" /** Store the result in reversed_result. */
        :
        : "r"(reversed_a), "r"(reversed_b), "r"(reversed_result)
        : "memory", "cc", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5");

    /**
     * Reverse the byte order of the result to convert it back to big-endian format.
     */
    for (index = 0; index < 16; index++)
        result[index] = reversed_result[15 - index];

    return;
}

/**
 * Multiplies x by H in GF(2^128) using precomputed tables.
 * Used in GCM for authenticated encryption.
 *
 * @param gcm_context     GCM context with precomputed tables.
 * @param input_block     Input element (16 bytes).
 * @param result_block    Output buffer (16 bytes).
 */
static void gcm_multiply_by_hash_key(GCM_ctx *gcm_context, const unsigned char input_block[16], unsigned char result_block[16])
{
    int byte_index = 0;
    unsigned char lower_nibble, upper_nibble, remainder;
    uint64_t high_bits, low_bits;

    // Use AES-NI if available for faster computation.
    if (API_AES_checkHWsupport() == hardware_AES_NI)
    {
        unsigned char precomputed_h[16];

        // Prepare H from precomputed tables.
        INSERT_UINT32_BE(gcm_context->HH[8] >> 32, precomputed_h, 0);
        INSERT_UINT32_BE(gcm_context->HH[8], precomputed_h, 4);
        INSERT_UINT32_BE(gcm_context->HL[8] >> 32, precomputed_h, 8);
        INSERT_UINT32_BE(gcm_context->HL[8], precomputed_h, 12);

        // Multiply using AES-NI.
        aesni_gcm_multiply(result_block, input_block, precomputed_h);
        return;
    }

    // Fallback to software implementation.
    lower_nibble = input_block[15] & 0xf;
    high_bits = gcm_context->HH[lower_nibble];
    low_bits = gcm_context->HL[lower_nibble];

    // Process each byte of the input block, starting from the end.
    for (byte_index = 15; byte_index >= 0; byte_index--)
    {
        lower_nibble = input_block[byte_index] & 0xf;
        upper_nibble = input_block[byte_index] >> 4;

        // Reduction step for all bytes except the last.
        if (byte_index != 15)
        {
            remainder = (unsigned char)low_bits & 0xf;
            low_bits = (high_bits << 60) | (low_bits >> 4);
            high_bits = (high_bits >> 4);
            high_bits ^= (uint64_t)gf128_mult_table_last4[remainder] << 48;
            high_bits ^= gcm_context->HH[lower_nibble];
            low_bits ^= gcm_context->HL[lower_nibble];
        }

        // Process the upper 4 bits of the current byte.
        remainder = (unsigned char)low_bits & 0xf;
        low_bits = (high_bits << 60) | (low_bits >> 4);
        high_bits = (high_bits >> 4);
        high_bits ^= (uint64_t)gf128_mult_table_last4[remainder] << 48;
        high_bits ^= gcm_context->HH[upper_nibble];
        low_bits ^= gcm_context->HL[upper_nibble];
    }

    // Store the final result in the output buffer.
    INSERT_UINT32_BE(high_bits >> 32, result_block, 0);
    INSERT_UINT32_BE(high_bits, result_block, 4);
    INSERT_UINT32_BE(low_bits >> 32, result_block, 8);
    INSERT_UINT32_BE(low_bits, result_block, 12);
}

int gcm_initialize_operation(GCM_ctx *gcm_context, int operation_mode, const unsigned char *iv, size_t iv_length, const unsigned char *aad, size_t aad_length)
{
    int ret;
    unsigned char iv_work_buffer[16]; // Temporary buffer for IV processing.
    size_t i;
    const unsigned char *current_position;
    size_t chunk_length, output_length = 0;

    /* Ensure IV and AAD lengths are within the allowed limit (2^64 bits). */
    if (((uint64_t)iv_length) >> 61 != 0 ||
        ((uint64_t)aad_length) >> 61 != 0)
    {
        printf("Invalid input: IV or AAD length exceeds the allowed limit.\n");
        return -1;
    }

    // Initialize GCM context fields.
    memset(gcm_context->y, 0x00, sizeof(gcm_context->y));
    memset(gcm_context->buf, 0x00, sizeof(gcm_context->buf));

    gcm_context->mode = operation_mode;
    gcm_context->len = 0;
    gcm_context->add_len = 0;

    // Process the IV based on its length.
    if (iv_length == 12)
    {
        // For a 12-byte IV, copy it directly and set the counter to 1.
        memcpy(gcm_context->y, iv, iv_length);
        gcm_context->y[15] = 1;
    }
    else
    {
        // For IVs of other lengths, use the GHASH function to process them.
        memset(iv_work_buffer, 0x00, 16);
        INSERT_UINT32_BE(iv_length * 8, iv_work_buffer, 12); // Encode IV length in bits.

        current_position = iv;
        while (iv_length > 0)
        {
            chunk_length = (iv_length < 16) ? iv_length : 16; // Process in 16-byte chunks.

            // XOR the IV chunk into the GCM context.
            for (i = 0; i < chunk_length; i++)
                gcm_context->y[i] ^= current_position[i];

            // Multiply by the hash key (H) in GF(2^128).
            gcm_multiply_by_hash_key(gcm_context, gcm_context->y, gcm_context->y);

            iv_length -= chunk_length;
            current_position += chunk_length;
        }

        // XOR the encoded IV length into the GCM context.
        for (i = 0; i < 16; i++)
            gcm_context->y[i] ^= iv_work_buffer[i];

        // Multiply by the hash key (H) in GF(2^128).
        gcm_multiply_by_hash_key(gcm_context, gcm_context->y, gcm_context->y);
    }

    // Encrypt the processed IV to generate the base ECTR (counter mode) value.
    API_AES_encrypt_block(&(gcm_context->cipher_ctx), gcm_context->y, gcm_context->base_ectr);

    // Process the Additional Authenticated Data (AAD).
    gcm_context->add_len = aad_length;
    current_position = aad;
    while (aad_length > 0)
    {
        chunk_length = (aad_length < 16) ? aad_length : 16; // Process in 16-byte chunks.

        // XOR the AAD chunk into the GCM context.
        for (i = 0; i < chunk_length; i++)
            gcm_context->buf[i] ^= current_position[i];

        // Multiply by the hash key (H) in GF(2^128).
        gcm_multiply_by_hash_key(gcm_context, gcm_context->buf, gcm_context->buf);

        aad_length -= chunk_length;
        current_position += chunk_length;
    }

    return 0; // Success.
}

int gcm_process_data(GCM_ctx *gcm_context, size_t data_length, const unsigned char *input_data, unsigned char *output_data)
{
    int ret;
    unsigned char encrypted_counter[16]; // Buffer for the encrypted counter.
    size_t i;
    const unsigned char *input_ptr;
    unsigned char *output_ptr = output_data;
    size_t chunk_length, output_len = 0;

    // Check for overlapping input and output buffers.
    if (output_data > input_data && (size_t)(output_data - input_data) < data_length)
    {
        return -1; // Error: overlapping buffers.
    }

    /* Ensure the total length of processed data does not exceed the GCM limit (2^36 - 2^5 bytes).
     * Also, check for potential overflow. */
    if (gcm_context->len + data_length < gcm_context->len ||
        (uint64_t)gcm_context->len + data_length > 0xFFFFFFFE0ull)
    {
        return -1; // Error: data length exceeds the allowed limit.
    }

    // Update the total length of processed data.
    gcm_context->len += data_length;

    // Process the input data in chunks of 16 bytes (or less for the last chunk).
    input_ptr = input_data;
    while (data_length > 0)
    {
        chunk_length = (data_length < 16) ? data_length : 16; // Determine the chunk size.

        // Increment the counter (y) for the next block.
        for (i = 16; i > 12; i--)
        {
            if (++gcm_context->y[i - 1] != 0)
                break; // Stop if there is no carryover.
        }

        // Encrypt the counter to produce the ECTR (Encrypted Counter) value.
        API_AES_encrypt_block(&gcm_context->cipher_ctx, gcm_context->y, encrypted_counter);

        // Process each byte in the chunk.
        for (i = 0; i < chunk_length; i++)
        {
            if (gcm_context->mode == 2) // 2 es descifrar, recuerdalo también bro
            {
                gcm_context->buf[i] ^= input_ptr[i]; // XOR input with the GHASH buffer.
            }

            // XOR the encrypted counter with the input to produce the output.
            output_ptr[i] = encrypted_counter[i] ^ input_ptr[i];

            if (gcm_context->mode == 1) // es cifrar, recuerdalo para ponerlo después
            {
                gcm_context->buf[i] ^= output_ptr[i]; // XOR output with the GHASH buffer.
            }
        }

        // Multiply the GHASH buffer by the hash key (H) in GF(2^128).
        gcm_multiply_by_hash_key(gcm_context, gcm_context->buf, gcm_context->buf);

        // Move to the next chunk.
        data_length -= chunk_length;
        input_ptr += chunk_length;
        output_ptr += chunk_length;
    }

    return 0; // Success.
}

int gcm_finalize_operation(GCM_ctx *gcm_context,
                           unsigned char *auth_tag,
                           size_t auth_tag_length)
{
    unsigned char final_buffer[16]; // Temporary buffer for final computations.
    size_t i;
    uint64_t total_data_length_bits = gcm_context->len * 8;    // Total data length in bits.
    uint64_t total_aad_length_bits = gcm_context->add_len * 8; // Total AAD length in bits.

    // Validate the authentication tag length.
    if (auth_tag_length > 16 || auth_tag_length < 4)
    {
        return -1; // Error: invalid tag length.
    }

    // Copy the base ECTR (Encrypted Counter) to the tag if a tag buffer is provided.
    if (auth_tag_length != 0)
    {
        memcpy(auth_tag, gcm_context->base_ectr, auth_tag_length);
    }

    // If there is any data or AAD processed, compute the final tag.
    if (total_data_length_bits || total_aad_length_bits)
    {
        // Prepare the final buffer with the lengths of the data and AAD.
        memset(final_buffer, 0x00, 16);
        INSERT_UINT32_BE((total_aad_length_bits >> 32), final_buffer, 0);
        INSERT_UINT32_BE((total_aad_length_bits), final_buffer, 4);
        INSERT_UINT32_BE((total_data_length_bits >> 32), final_buffer, 8);
        INSERT_UINT32_BE((total_data_length_bits), final_buffer, 12);

        // XOR the lengths into the GHASH buffer.
        for (i = 0; i < 16; i++)
        {
            gcm_context->buf[i] ^= final_buffer[i];
        }

        // Multiply the GHASH buffer by the hash key (H) in GF(2^128).
        gcm_multiply_by_hash_key(gcm_context, gcm_context->buf, gcm_context->buf);

        // XOR the GHASH buffer with the base ECTR to produce the final tag.
        for (i = 0; i < auth_tag_length; i++)
        {
            auth_tag[i] ^= gcm_context->buf[i];
        }
    }

    return 0; // Success.
}

int gcm_encrypt_decrypt_and_tag(GCM_ctx *gcm_context, int operation_mode, size_t data_length, const unsigned char *iv, size_t iv_length, const unsigned char *aad,
                                size_t aad_length, const unsigned char *input_data, unsigned char *output_data, size_t tag_length, unsigned char *auth_tag)
{
    int ret;

    // Initialize the GCM operation.
    if ((ret = gcm_initialize_operation(gcm_context, operation_mode, iv, iv_length, aad, aad_length)) != 0)
    {
        printf("Error: Failed to initialize GCM operation.\n");
        return ret;
    }

    // Process the input data.
    if ((ret = gcm_process_data(gcm_context, data_length, input_data, output_data)) != 0)
    {
        printf("Error: Failed to process data in GCM mode.\n");
        return ret;
    }

    // Finalize the operation and generate the authentication tag.
    if ((ret = gcm_finalize_operation(gcm_context, auth_tag, tag_length)) != 0)
    {
        printf("Error: Failed to finalize GCM operation and generate tag.\n");
        return ret;
    }

    return 0; // Success.
}

