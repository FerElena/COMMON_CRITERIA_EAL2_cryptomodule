#include "AES_GCM.h"

#define EXTRACT_UINT32_BE(var, buf, idx)                                                                                                   \
    {                                                                                                                                      \
        (var) = ((uint32_t)(buf)[(idx)] << 24) | ((uint32_t)(buf)[(idx) + 1] << 16) | ((uint32_t)(buf)[(idx) + 2] << 8) | ((uint32_t)(buf)[(idx) + 3]); \
    }

#define INSERT_UINT32_BE(var, buf, idx)                      \
    {                                                        \
        (buf)[(idx)] = (unsigned char)((var) >> 24);         \
        (buf)[(idx) + 1] = (unsigned char)((var) >> 16);     \
        (buf)[(idx) + 2] = (unsigned char)((var) >> 8);      \
        (buf)[(idx) + 3] = (unsigned char)((var));           \
    }


static int gcm_gen_table(GCM_ctx *ctx)
{
    int ret, i, j;
    uint64_t hi, lo;
    uint64_t vl, vh;
    unsigned char h[16];
    unsigned char aux[16];
    size_t olen = 0;

    memset(aux, 0, 16);
    API_AES_encrypt_block(&(ctx->cipher_ctx), aux, h); // habria que inicializar el contexto con la clave primero!!!!!!!!!!!!!!!!!!!
    /* pack h as two 64-bits ints, big-endian */
    EXTRACT_UINT32_BE(hi, h, 0);
    EXTRACT_UINT32_BE(lo, h, 4);
    vh = (uint64_t)hi << 32 | lo;

    EXTRACT_UINT32_BE(hi, h, 8);
    EXTRACT_UINT32_BE(lo, h, 12);
    vl = (uint64_t)hi << 32 | lo;

    /* 8 = 1000 corresponds to 1 in GF(2^128) */
    ctx->HL[8] = vl;
    ctx->HH[8] = vh;


    if (API_AES_checkHWsupport() == hardware_AES_NI ) // we dont need generate more tables in sace we are usign hardware AES-NI instructions
        return (0);

    /* 0 corresponds to 0 in GF(2^128) */
    ctx->HH[0] = 0;
    ctx->HL[0] = 0;

    for (i = 4; i > 0; i >>= 1)
    {
        uint32_t T = (vl & 1) * 0xe1000000U;
        vl = (vh << 63) | (vl >> 1);
        vh = (vh >> 1) ^ ((uint64_t)T << 32);

        ctx->HL[i] = vl;
        ctx->HH[i] = vh;
    }

    for (i = 2; i <= 8; i *= 2)
    {
        uint64_t *HiL = ctx->HL + i, *HiH = ctx->HH + i;
        vh = *HiH;
        vl = *HiL;
        for (j = 1; j < i; j++)
        {
            HiH[j] = vh ^ ctx->HH[j];
            HiL[j] = vl ^ ctx->HL[j];
        }
    }

    return (0);
}

int mbedtls_gcm_setkey(GCM_ctx *ctx,
                       const unsigned char *key,
                       unsigned int keybits)
{
    int ret;

    if ((ret = gcm_gen_table(ctx)) != 0)
        return (ret);

    return (0);
}

/*
 * Shoup's method for multiplication use this table with
 *      last4[x] = x times P^128
 * where x and last4[x] are seen as elements of GF(2^128) as in [MGV]
 */
static const uint64_t last4[16] =
    {
        0x0000, 0x1c20, 0x3840, 0x2460,
        0x7080, 0x6ca0, 0x48c0, 0x54e0,
        0xe100, 0xfd20, 0xd940, 0xc560,
        0x9180, 0x8da0, 0xa9c0, 0xb5e0};

#define PCLMULQDQ ".byte 0x66,0x0F,0x3A,0x44,"
#define xmm0_xmm0   "0xC0"
#define xmm0_xmm1   "0xC8"
#define xmm0_xmm2   "0xD0"
#define xmm0_xmm3   "0xD8"
#define xmm0_xmm4   "0xE0"
#define xmm1_xmm0   "0xC1"
#define xmm1_xmm2   "0xD1"

void mbedtls_aesni_gcm_mult(unsigned char c[16], const unsigned char a[16], const unsigned char b[16])
{
    unsigned char aa[16], bb[16], cc[16];
    size_t i;

    /* The inputs are in big-endian order, so byte-reverse them */
    for (i = 0; i < 16; i++)
    {
        aa[i] = a[15 - i];
        bb[i] = b[15 - i];
    }

    asm("movdqu (%0), %%xmm0               \n\t" // a1:a0
        "movdqu (%1), %%xmm1               \n\t" // b1:b0

        /*
         * Caryless multiplication xmm2:xmm1 = xmm0 * xmm1
         * using [CLMUL-WP] algorithm 1 (p. 13).
         */
        "movdqa %%xmm1, %%xmm2             \n\t" // copy of b1:b0
        "movdqa %%xmm1, %%xmm3             \n\t" // same
        "movdqa %%xmm1, %%xmm4             \n\t" // same
        PCLMULQDQ xmm0_xmm1 ",0x00         \n\t" // a0*b0 = c1:c0
        PCLMULQDQ xmm0_xmm2 ",0x11         \n\t" // a1*b1 = d1:d0
        PCLMULQDQ xmm0_xmm3 ",0x10         \n\t" // a0*b1 = e1:e0
        PCLMULQDQ xmm0_xmm4 ",0x01         \n\t" // a1*b0 = f1:f0
        "pxor %%xmm3, %%xmm4               \n\t" // e1+f1:e0+f0
        "movdqa %%xmm4, %%xmm3             \n\t" // same
        "psrldq $8, %%xmm4                 \n\t" // 0:e1+f1
        "pslldq $8, %%xmm3                 \n\t" // e0+f0:0
        "pxor %%xmm4, %%xmm2               \n\t" // d1:d0+e1+f1
        "pxor %%xmm3, %%xmm1               \n\t" // c1+e0+f1:c0

        /*
         * Now shift the result one bit to the left,
         * taking advantage of [CLMUL-WP] eq 27 (p. 20)
         */
        "movdqa %%xmm1, %%xmm3             \n\t" // r1:r0
        "movdqa %%xmm2, %%xmm4             \n\t" // r3:r2
        "psllq $1, %%xmm1                  \n\t" // r1<<1:r0<<1
        "psllq $1, %%xmm2                  \n\t" // r3<<1:r2<<1
        "psrlq $63, %%xmm3                 \n\t" // r1>>63:r0>>63
        "psrlq $63, %%xmm4                 \n\t" // r3>>63:r2>>63
        "movdqa %%xmm3, %%xmm5             \n\t" // r1>>63:r0>>63
        "pslldq $8, %%xmm3                 \n\t" // r0>>63:0
        "pslldq $8, %%xmm4                 \n\t" // r2>>63:0
        "psrldq $8, %%xmm5                 \n\t" // 0:r1>>63
        "por %%xmm3, %%xmm1                \n\t" // r1<<1|r0>>63:r0<<1
        "por %%xmm4, %%xmm2                \n\t" // r3<<1|r2>>62:r2<<1
        "por %%xmm5, %%xmm2                \n\t" // r3<<1|r2>>62:r2<<1|r1>>63

        /*
         * Now reduce modulo the GCM polynomial x^128 + x^7 + x^2 + x + 1
         * using [CLMUL-WP] algorithm 5 (p. 20).
         * Currently xmm2:xmm1 holds x3:x2:x1:x0 (already shifted).
         */
        /* Step 2 (1) */
        "movdqa %%xmm1, %%xmm3             \n\t" // x1:x0
        "movdqa %%xmm1, %%xmm4             \n\t" // same
        "movdqa %%xmm1, %%xmm5             \n\t" // same
        "psllq $63, %%xmm3                 \n\t" // x1<<63:x0<<63 = stuff:a
        "psllq $62, %%xmm4                 \n\t" // x1<<62:x0<<62 = stuff:b
        "psllq $57, %%xmm5                 \n\t" // x1<<57:x0<<57 = stuff:c

        /* Step 2 (2) */
        "pxor %%xmm4, %%xmm3               \n\t" // stuff:a+b
        "pxor %%xmm5, %%xmm3               \n\t" // stuff:a+b+c
        "pslldq $8, %%xmm3                 \n\t" // a+b+c:0
        "pxor %%xmm3, %%xmm1               \n\t" // x1+a+b+c:x0 = d:x0

        /* Steps 3 and 4 */
        "movdqa %%xmm1,%%xmm0              \n\t" // d:x0
        "movdqa %%xmm1,%%xmm4              \n\t" // same
        "movdqa %%xmm1,%%xmm5              \n\t" // same
        "psrlq $1, %%xmm0                  \n\t" // e1:x0>>1 = e1:e0'
        "psrlq $2, %%xmm4                  \n\t" // f1:x0>>2 = f1:f0'
        "psrlq $7, %%xmm5                  \n\t" // g1:x0>>7 = g1:g0'
        "pxor %%xmm4, %%xmm0               \n\t" // e1+f1:e0'+f0'
        "pxor %%xmm5, %%xmm0               \n\t" // e1+f1+g1:e0'+f0'+g0'
        // e0'+f0'+g0' is almost e0+f0+g0, ex\tcept for some missing
        // bits carried from d. Now get those\t bits back in.
        "movdqa %%xmm1,%%xmm3              \n\t" // d:x0
        "movdqa %%xmm1,%%xmm4              \n\t" // same
        "movdqa %%xmm1,%%xmm5              \n\t" // same
        "psllq $63, %%xmm3                 \n\t" // d<<63:stuff
        "psllq $62, %%xmm4                 \n\t" // d<<62:stuff
        "psllq $57, %%xmm5                 \n\t" // d<<57:stuff
        "pxor %%xmm4, %%xmm3               \n\t" // d<<63+d<<62:stuff
        "pxor %%xmm5, %%xmm3               \n\t" // missing bits of d:stuff
        "psrldq $8, %%xmm3                 \n\t" // 0:missing bits of d
        "pxor %%xmm3, %%xmm0               \n\t" // e1+f1+g1:e0+f0+g0
        "pxor %%xmm1, %%xmm0               \n\t" // h1:h0
        "pxor %%xmm2, %%xmm0               \n\t" // x3+h1:x2+h0

        "movdqu %%xmm0, (%2)               \n\t" // done
        :
        : "r"(aa), "r"(bb), "r"(cc)
        : "memory", "cc", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5");

    /* Now byte-reverse the outputs */
    for (i = 0; i < 16; i++)
        c[i] = cc[15 - i];

    return;
}

#define MBEDTLS_AESNI_C
#define MBEDTLS_HAVE_X86_64
/*
 * Sets output to x times H using the precomputed tables.
 * x and output are seen as elements of GF(2^128) as in [MGV].
 */
static void gcm_mult(GCM_ctx *ctx, const unsigned char x[16],
                     unsigned char output[16])
{
    int i = 0;
    unsigned char lo, hi, rem;
    uint64_t zh, zl;
    if(API_AES_checkHWsupport() == hardware_AES_NI){ // we can use AES-NI and 128 bits registers to perform 
        unsigned char h[16];

            INSERT_UINT32_BE(ctx->HH[8] >> 32, h, 0);
            INSERT_UINT32_BE(ctx->HH[8], h, 4);
            INSERT_UINT32_BE(ctx->HL[8] >> 32, h, 8);
            INSERT_UINT32_BE(ctx->HL[8], h, 12);

            mbedtls_aesni_gcm_mult(output, x, h);
            return;
    }

    lo = x[15] & 0xf;

    zh = ctx->HH[lo];
    zl = ctx->HL[lo];

    for (i = 15; i >= 0; i--)
    {
        lo = x[i] & 0xf;
        hi = x[i] >> 4;

        if (i != 15)
        {
            rem = (unsigned char)zl & 0xf;
            zl = (zh << 60) | (zl >> 4);
            zh = (zh >> 4);
            zh ^= (uint64_t)last4[rem] << 48;
            zh ^= ctx->HH[lo];
            zl ^= ctx->HL[lo];
        }

        rem = (unsigned char)zl & 0xf;
        zl = (zh << 60) | (zl >> 4);
        zh = (zh >> 4);
        zh ^= (uint64_t)last4[rem] << 48;
        zh ^= ctx->HH[hi];
        zl ^= ctx->HL[hi];
    }

    INSERT_UINT32_BE(zh >> 32, output, 0);
    INSERT_UINT32_BE(zh, output, 4);
    INSERT_UINT32_BE(zl >> 32, output, 8);
    INSERT_UINT32_BE(zl, output, 12);
}

int mbedtls_gcm_starts(GCM_ctx *ctx,
                       int mode,
                       const unsigned char *iv,
                       size_t iv_len,
                       const unsigned char *add,
                       size_t add_len)
{
    int ret;
    unsigned char work_buf[16];
    size_t i;
    const unsigned char *p;
    size_t use_len, olen = 0;

    /* IV and AD are limited to 2^64 bits, so 2^61 bytes */
    if (((uint64_t)iv_len) >> 61 != 0 ||
        ((uint64_t)add_len) >> 61 != 0)
    {
        printf("bad input\n");
        return -1;
    }

    memset(ctx->y, 0x00, sizeof(ctx->y));
    memset(ctx->buf, 0x00, sizeof(ctx->buf));

    ctx->mode = mode;
    ctx->len = 0;
    ctx->add_len = 0;

    if (iv_len == 12)
    {
        memcpy(ctx->y, iv, iv_len);
        ctx->y[15] = 1;
    }
    else
    {
        memset(work_buf, 0x00, 16);
        INSERT_UINT32_BE(iv_len * 8, work_buf, 12);

        p = iv;
        while (iv_len > 0)
        {
            use_len = (iv_len < 16) ? iv_len : 16;

            for (i = 0; i < use_len; i++)
                ctx->y[i] ^= p[i];

            gcm_mult(ctx, ctx->y, ctx->y);

            iv_len -= use_len;
            p += use_len;
        }

        for (i = 0; i < 16; i++)
            ctx->y[i] ^= work_buf[i];

        gcm_mult(ctx, ctx->y, ctx->y);
    }

    /*
    if ((ret = mbedtls_cipher_update(&ctx->cipher_ctx, ctx->y, 16, ctx->base_ectr,
                                     &olen)) != 0)
    {
        printf("close\n");
        return (ret);
    }
    */

    API_AES_encrypt_block(&(ctx->cipher_ctx), ctx->y, ctx->base_ectr);

    ctx->add_len = add_len;
    p = add;
    while (add_len > 0)
    {
        use_len = (add_len < 16) ? add_len : 16;

        for (i = 0; i < use_len; i++)
            ctx->buf[i] ^= p[i];

        gcm_mult(ctx, ctx->buf, ctx->buf);

        add_len -= use_len;
        p += use_len;
    }

    return (0);
}

int mbedtls_gcm_update(GCM_ctx *ctx,
                       size_t length,
                       const unsigned char *input,
                       unsigned char *output)
{
    int ret;
    unsigned char ectr[16];
    size_t i;
    const unsigned char *p;
    unsigned char *out_p = output;
    size_t use_len, olen = 0;

    if (output > input && (size_t)(output - input) < length)
        return (-1);

    /* Total length is restricted to 2^39 - 256 bits, ie 2^36 - 2^5 bytes
     * Also check for possible overflow */
    if (ctx->len + length < ctx->len ||
        (uint64_t)ctx->len + length > 0xFFFFFFFE0ull)
    {
        return (-1);
    }

    ctx->len += length;

    p = input;
    while (length > 0)
    {
        use_len = (length < 16) ? length : 16;

        for (i = 16; i > 12; i--)
            if (++ctx->y[i - 1] != 0)
                break;
        /*
                if ((ret = mbedtls_cipher_update(&ctx->cipher_ctx, ctx->y, 16, ectr,
                                                 &olen)) != 0)
                {
                    return (ret);
                }
        */
        API_AES_encrypt_block(&ctx->cipher_ctx, ctx->y, ectr);

        for (i = 0; i < use_len; i++)
        {
            if (ctx->mode == 2) // 2 es desencriptar, recuerdalo también bro
                ctx->buf[i] ^= p[i];
            out_p[i] = ectr[i] ^ p[i];
            if (ctx->mode == 1) // 1 es encryptar, recuerdalo para ponerlo después
                ctx->buf[i] ^= out_p[i];
        }

        gcm_mult(ctx, ctx->buf, ctx->buf);

        length -= use_len;
        p += use_len;
        out_p += use_len;
    }

    return (0);
}

int mbedtls_gcm_finish(GCM_ctx *ctx,
                       unsigned char *tag,
                       size_t tag_len)
{
    unsigned char work_buf[16];
    size_t i;
    uint64_t orig_len = ctx->len * 8;
    uint64_t orig_add_len = ctx->add_len * 8;

    if (tag_len > 16 || tag_len < 4)
        return (-1);

    if (tag_len != 0)
        memcpy(tag, ctx->base_ectr, tag_len);

    if (orig_len || orig_add_len)
    {
        memset(work_buf, 0x00, 16);

        INSERT_UINT32_BE((orig_add_len >> 32), work_buf, 0);
        INSERT_UINT32_BE((orig_add_len), work_buf, 4);
        INSERT_UINT32_BE((orig_len >> 32), work_buf, 8);
        INSERT_UINT32_BE((orig_len), work_buf, 12);

        for (i = 0; i < 16; i++)
            ctx->buf[i] ^= work_buf[i];

        gcm_mult(ctx, ctx->buf, ctx->buf);

        for (i = 0; i < tag_len; i++)
            tag[i] ^= ctx->buf[i];
    }

    return (0);
}

int mbedtls_gcm_crypt_and_tag(GCM_ctx *ctx,
                              int mode,
                              size_t length,
                              const unsigned char *iv,
                              size_t iv_len,
                              const unsigned char *add,
                              size_t add_len,
                              const unsigned char *input,
                              unsigned char *output,
                              size_t tag_len,
                              unsigned char *tag)
{
    int ret;

    if ((ret = mbedtls_gcm_starts(ctx, mode, iv, iv_len, add, add_len)) != 0)
    {
        printf("one\n");
        return (ret);
    }

    if ((ret = mbedtls_gcm_update(ctx, length, input, output)) != 0)
    {
        printf("two\n");
        return (ret);
    }

    if ((ret = mbedtls_gcm_finish(ctx, tag, tag_len)) != 0)
    {
        printf("three\n");
        return (ret);
    }

    return (0);
}

int mbedtls_gcm_auth_decrypt(GCM_ctx *ctx,
                             size_t length,
                             const unsigned char *iv,
                             size_t iv_len,
                             const unsigned char *add,
                             size_t add_len,
                             const unsigned char *tag,
                             size_t tag_len,
                             const unsigned char *input,
                             unsigned char *output)
{
    int ret;
    unsigned char check_tag[16];
    size_t i;
    int diff;

    if ((ret = mbedtls_gcm_crypt_and_tag(ctx, 2, length,
                                         iv, iv_len, add, add_len,
                                         input, output, tag_len, check_tag)) != 0)
    {
        return (ret);
    }

    /* Check tag in "constant-time" */
    for (diff = 0, i = 0; i < tag_len; i++)
        diff |= tag[i] ^ check_tag[i];

    if (diff != 0)
    {
        return (-1);
    }

    return (0);
}