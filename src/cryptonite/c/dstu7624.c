/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdio.h>
#include <memory.h>

#include "dstu7624.h"
#include "byte_utils_internal.h"
#include "byte_array_internal.h"
#include "math_gf2m_internal.h"
#include "macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/dstu7624.c"

#define REDUCTION_POLYNOMIAL 0x11d  /* x^8 + x^4 + x^3 + x^2 + 1 */
#define ROWS 8
#define MAX_NUM_IN_BYTE 256
#define MAX_BLOCK_LEN 64
#define BITS_IN_BYTE 8
#define KALINA_128_KEY_LEN 16
#define KALINA_256_KEY_LEN 32
#define KALINA_512_KEY_LEN 64
#define KALINA_128_BLOCK_LEN 16
#define KALINA_256_BLOCK_LEN 32
#define KALINA_512_BLOCK_LEN 64
#define SBOX_LEN 1024

#define GALUA_MUL(i, j, k, shift) (uint64_t)((uint64_t)multiply_galua(mds_matrix[j * ROWS + k], s_blocks[(k % 4) * MAX_NUM_IN_BYTE + i]) << ((uint64_t)shift))

typedef enum {
    DSTU7624_MODE_ECB,
    DSTU7624_MODE_CTR,
    DSTU7624_MODE_OFB,
    DSTU7624_MODE_CFB,
    DSTU7624_MODE_CBC,
    DSTU7624_MODE_CMAC,
    DSTU7624_MODE_KW,
    DSTU7624_MODE_XTS,
    DSTU7624_MODE_CCM,
    DSTU7624_MODE_GCM,
    DSTU7624_MODE_GMAC
} Dstu7624Mode;

typedef struct Dstu7624CtrCtx_st {
    uint8_t gamma[64];
    uint8_t feed[64];
    size_t used_gamma_len;
} Dstu7624CtrCtx;

typedef struct Dstu7624OfbCtx_st {
    uint8_t gamma[64];
    size_t used_gamma_len;
} Dstu7624OfbCtx;

typedef struct Dstu7624CbcCtx_st {
    uint8_t gamma[64];
} Dstu7624CbcCtx;

typedef struct Dstu7624CfbCtx_st {
    size_t q;
    uint8_t gamma[64];
    uint8_t feed[64];
    size_t used_gamma_len;
} Dstu7624CfbCtx;

typedef struct Dstu7624GmacCtx_st {
    uint64_t H[8];
    uint64_t B[8];
    uint8_t last_block[MAX_BLOCK_LEN];
    size_t last_block_len;
    size_t msg_tot_len;
    size_t q;
    Gf2mCtx *gf2m_ctx;
} Dstu7624GmacCtx;

typedef struct Dstu7624GcmCtx_st {
    uint64_t iv[8];
    size_t q;
    Gf2mCtx *gf2m_ctx;
} Dstu7624GcmCtx;

typedef struct Dstu7624CcmCtx_st {
    size_t q;
    const ByteArray *key;
    const ByteArray *iv_tmp;
    uint8_t iv[MAX_BLOCK_LEN];
    size_t nb;
} Dstu7624CcmCtx;

typedef struct Dstu7624XtsCtx_st {
    uint8_t iv[64];
    Gf2mCtx *gf2m_ctx;
} Dstu7624XtsCtx;

typedef struct Dstu7624CmacCtx_st {
    size_t q;
    uint8_t last_block[ROWS * ROWS];
    size_t lblock_len;
} Dstu7624CmacCtx;

struct Dstu7624Ctx_st {
    Dstu7624Mode mode_id;
    uint64_t p_boxrowcol[ROWS][MAX_NUM_IN_BYTE];
    uint64_t p_boxrowcol_rev[ROWS][MAX_NUM_IN_BYTE];
    uint8_t sbox[SBOX_LEN];
    uint8_t sbox_rev[SBOX_LEN];
    uint64_t p_rkeys[MAX_BLOCK_LEN * 20];
    uint64_t p_rkeys_rev[MAX_BLOCK_LEN * 20];
    uint64_t state[ROWS];
    size_t key_len;
    size_t block_len;
    size_t rounds;

    union {
        Dstu7624CtrCtx ctr;
        Dstu7624OfbCtx ofb;
        Dstu7624CbcCtx cbc;
        Dstu7624CfbCtx cfb;
        Dstu7624GmacCtx gmac;
        Dstu7624GcmCtx gcm;
        Dstu7624CcmCtx ccm;
        Dstu7624XtsCtx xts;
        Dstu7624CmacCtx cmac;
    } mode;

    void (*basic_transform)(Dstu7624Ctx *, uint64_t *);
    void (*subrowcol)(uint64_t *, Dstu7624Ctx *); /*store pointer on each subshiftmix for all block size type*/
    void (*subrowcol_dec)(Dstu7624Ctx *, uint64_t *); /*store pointer on each subshiftmix for all block size type*/
};


/*
 *             KALINA G DEFINITION
 * Macros for fast calculating m_col operation.
 * G128, G256, G512 - block length in bits
 * big_table - precomputed table of s_box and m_col operations (uint8_t)
 * in - data before s_box and m_col operations (uint64_t)
 * out - data after m_col operation (uint64_t)
 * z0...z7 - columns number
 * Example:
 * G128 - 128 bit, 16 byte block, kalina representation state: 8x2, 2 columns,
 * there will be only 4 last values shifted, z0,...,z3 == 0, z4,...,z7 == 1.
 * It means, than z4,...,z7 will be taken from the next column
 */
#define kalina_G128(big_table, in, out, z0, z1, z2, z3, z4, z5, z6, z7)\
        out[0] =(uint64_t)big_table[ 0 ] [( (in[ z0 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z1 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z2 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z3 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z4 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z5 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z6 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z7 ] >> ( 7 * 8) ) & 0xFF)];\
        out[1] =(uint64_t)big_table[ 0 ] [( (in[ z4 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z5 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z6 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z7 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z0 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z1 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z2 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z3 ] >> ( 7 * 8) ) & 0xFF)]

#define kalina_G256(big_table, in, out, z0, z1, z2, z3, z4, z5, z6, z7)\
        out[0] =(uint64_t)big_table[ 0 ] [( (in[ z0 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z1 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z2 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z3 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z4 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z5 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z6 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z7 ] >> ( 7 * 8) ) & 0xFF)];\
        out[1] =(uint64_t)big_table[ 0 ] [( (in[ z7 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z6 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z0 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z1 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z2 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z3 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z4 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z5 ] >> ( 7 * 8) ) & 0xFF)];\
        out[2] =(uint64_t)big_table[ 0 ] [( (in[ z4 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z5 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z6 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z7 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z0 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z1 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z2 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z3 ] >> ( 7 * 8) ) & 0xFF)];\
        out[3] =(uint64_t)big_table[ 0 ] [( (in[ z2 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z3 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z4 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z5 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z6 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z7 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z0 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z1 ] >> ( 7 * 8) ) & 0xFF)]

#define kalina_G512(big_table, in, out, z0, z1, z2, z3, z4, z5, z6, z7)\
        out[0] =(uint64_t)big_table[ 0 ] [( (in[ z0 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z1 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z2 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z3 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z4 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z5 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z6 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z7 ] >> ( 7 * 8) ) & 0xFF)];\
        out[1] =(uint64_t)big_table[ 0 ] [( (in[ z7 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z0 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z1 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z2 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z3 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z4 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z5 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z6 ] >> ( 7 * 8) ) & 0xFF)];\
        out[2] =(uint64_t)big_table[ 0 ] [( (in[ z6 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z7 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z0 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z1 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z2 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z3 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z4 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z5 ] >> ( 7 * 8) ) & 0xFF)];\
        out[3] =(uint64_t)big_table[ 0 ] [( (in[ z5 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z6 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z7 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z0 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z1 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z2 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z3 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z4 ] >> ( 7 * 8) ) & 0xFF)];\
        out[4] =(uint64_t)big_table[ 0 ] [( (in[ z4 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z5 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z6 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z7 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z0 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z1 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z2 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z3 ] >> ( 7 * 8) ) & 0xFF)];\
        out[5] =(uint64_t)big_table[ 0 ] [( (in[ z3 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z4 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z5 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z6 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z7 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z0 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z1 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z2 ] >> ( 7 * 8) ) & 0xFF)];\
        out[6] =(uint64_t)big_table[ 0 ] [( (in[ z2 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z3 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z4 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z5 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z6 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z7 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z0 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z1 ] >> ( 7 * 8) ) & 0xFF)];\
        out[7] =(uint64_t)big_table[ 0 ] [( (in[ z1 ] >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 1 ] [( (in[ z2 ] >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 2 ] [( (in[ z3 ] >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 3 ] [( (in[ z4 ] >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 4 ] [( (in[ z5 ] >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 5 ] [( (in[ z6 ] >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 6 ] [( (in[ z7 ] >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)big_table[ 7 ] [( (in[ z0 ] >> ( 7 * 8) ) & 0xFF)]

static void kalina_add(uint64_t *in, uint64_t *out, size_t size)
{
    switch (size) {
    case 2:
        out[0] += in[0];
        out[1] += in[1];
        break;
    case 4:
        out[0] += in[0];
        out[1] += in[1];
        out[2] += in[2];
        out[3] += in[3];
        break;
    case 8:
        out[0] += in[0];
        out[1] += in[1];
        out[2] += in[2];
        out[3] += in[3];
        out[4] += in[4];
        out[5] += in[5];
        out[6] += in[6];
        out[7] += in[7];
        break;
    default:
        break;
    }
}

/*memory safe xor*/
static void kalina_xor(void *arg1, void *arg2, size_t len, void *out)
{
    uint8_t *a8, *b8, *o8;
    uint64_t *a1 = arg1;
    uint64_t *a2 = arg2;
    uint64_t *o = out;
    size_t i;


    switch (len) {
    case 16:
        o[0] = a1[0] ^ a2[0];
        o[1] = a1[1] ^ a2[1];
        break;
    case 32:
        o[0] = a1[0] ^ a2[0];
        o[1] = a1[1] ^ a2[1];
        o[2] = a1[2] ^ a2[2];
        o[3] = a1[3] ^ a2[3];
        break;
    case 64:
        o[0] = a1[0] ^ a2[0];
        o[1] = a1[1] ^ a2[1];
        o[2] = a1[2] ^ a2[2];
        o[3] = a1[3] ^ a2[3];
        o[4] = a1[4] ^ a2[4];
        o[5] = a1[5] ^ a2[5];
        o[6] = a1[6] ^ a2[6];
        o[7] = a1[7] ^ a2[7];
        break;
    default:
        a8 = (uint8_t *) arg1;
        b8 = (uint8_t *) arg2;
        o8 = (uint8_t *) out;
        for (i = 0; i < len; i++) {
            o8[i] = a8[i] ^ b8[i];
        }
        break;
    }
}

/*s_box, s_row, m_col, xor operations*/
static void sub_shift_mix_xor(uint64_t *key, uint64_t *state, Dstu7624Ctx *ctx)
{
    ctx->subrowcol(state, ctx);
    kalina_xor(state, key, ctx->block_len, state);
}

/*s_box, s_row, m_col, add operations*/
static void sub_shift_mix_add(uint64_t *key, uint64_t *state, Dstu7624Ctx *ctx)
{
    ctx->subrowcol(state, ctx);
    kalina_add(key, state, ctx->block_len >> 3);
}

/*Matrix for m_col operation*/
static const uint8_t mds_matrix[MAX_BLOCK_LEN] = {
    0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04,
    0x04, 0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07,
    0x07, 0x04, 0x01, 0x01, 0x05, 0x01, 0x08, 0x06,
    0x06, 0x07, 0x04, 0x01, 0x01, 0x05, 0x01, 0x08,
    0x08, 0x06, 0x07, 0x04, 0x01, 0x01, 0x05, 0x01,
    0x01, 0x08, 0x06, 0x07, 0x04, 0x01, 0x01, 0x05,
    0x05, 0x01, 0x08, 0x06, 0x07, 0x04, 0x01, 0x01,
    0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04, 0x01
};

static const uint8_t mds_matrix_reverse[MAX_BLOCK_LEN] = {
    0xAD, 0x95, 0x76, 0xA8, 0x2F, 0x49, 0xD7, 0xCA,
    0xCA, 0xAD, 0x95, 0x76, 0xA8, 0x2F, 0x49, 0xD7,
    0xD7, 0xCA, 0xAD, 0x95, 0x76, 0xA8, 0x2F, 0x49,
    0x49, 0xD7, 0xCA, 0xAD, 0x95, 0x76, 0xA8, 0x2F,
    0x2F, 0x49, 0xD7, 0xCA, 0xAD, 0x95, 0x76, 0xA8,
    0xA8, 0x2F, 0x49, 0xD7, 0xCA, 0xAD, 0x95, 0x76,
    0x76, 0xA8, 0x2F, 0x49, 0xD7, 0xCA, 0xAD, 0x95,
    0x95, 0x76, 0xA8, 0x2F, 0x49, 0xD7, 0xCA, 0xAD
};

/*mcol operation with precomputed sbox and srow*/
#define BT_xor128(in, out, rkey) {\
    uint64_t i0 = in[0];\
    uint64_t i1 = in[1];\
    out[0] =(uint64_t) ctx->p_boxrowcol[ 0 ] [((i0 >> (0 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 1 ] [((i0 >> (1 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 2 ] [((i0 >> (2 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 3 ] [((i0 >> (3 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 4 ] [((i1 >> (4 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 5 ] [((i1 >> (5 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 6 ] [((i1 >> (6 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 7 ] [((i1 >> (7 * 8)) & 0xFF)]^*(rkey + 0);\
    out[1] =(uint64_t) ctx->p_boxrowcol[ 0 ] [((i1 >> (0 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 1 ] [((i1 >> (1 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 2 ] [((i1 >> (2 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 3 ] [((i1 >> (3 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 4 ] [((i0 >> (4 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 5 ] [((i0 >> (5 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 6 ] [((i0 >> (6 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 7 ] [((i0 >> (7 * 8)) & 0xFF)]^*(rkey + 1);\
}\

#define BT_add128(in, out, rkey) {\
    uint64_t i0 = in[0];\
    uint64_t i1 = in[1];\
    out[0] =((uint64_t) ctx->p_boxrowcol[ 0 ] [((i0 >> (0 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 1 ] [((i0 >> (1 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 2 ] [((i0 >> (2 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 3 ] [((i0 >> (3 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 4 ] [((i1 >> (4 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 5 ] [((i1 >> (5 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 6 ] [((i1 >> (6 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 7 ] [((i1 >> (7 * 8)) & 0xFF)]) + *(rkey + 0);\
    out[1] =((uint64_t) ctx->p_boxrowcol[ 0 ] [((i1 >> (0 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 1 ] [((i1 >> (1 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 2 ] [((i1 >> (2 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 3 ] [((i1 >> (3 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 4 ] [((i0 >> (4 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 5 ] [((i0 >> (5 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 6 ] [((i0 >> (6 * 8)) & 0xFF)]^\
            (uint64_t) ctx->p_boxrowcol[ 7 ] [((i0 >> (7 * 8)) & 0xFF)]) + *(rkey + 1);\
}\

#define BT_xor256(in, out, rkey){\
    uint64_t i0 = in[0];\
    uint64_t i1 = in[1];\
    uint64_t i2 = in[2];\
    uint64_t i3 = in[3];\
    out[0] =    (uint64_t) ctx->p_boxrowcol[ 0 ] [((i0 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i0 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i3 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i3 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i2 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i2 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i1 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i1 >> (7 * 8)) & 0xFF)] ^ *(rkey + 0);\
    out[1] =    (uint64_t) ctx->p_boxrowcol[ 0 ] [((i1 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i1 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i0 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i0 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i3 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i3 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i2 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i2 >> (7 * 8)) & 0xFF)] ^ *(rkey + 1);\
    out[2] =    (uint64_t) ctx->p_boxrowcol[ 0 ] [((i2 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i2 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i1 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i1 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i0 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i0 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i3 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i3 >> (7 * 8)) & 0xFF)] ^ *(rkey + 2);\
    out[3] =  (uint64_t) ctx->p_boxrowcol[ 0 ] [((i3 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i3 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i2 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i2 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i1 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i1 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i0 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i0 >> (7 * 8)) & 0xFF)] ^ *(rkey + 3);\
}\

#define BT_add256(in, out, rkey){\
    uint64_t i0 = in[0];\
    uint64_t i1 = in[1];\
    uint64_t i2 = in[2];\
    uint64_t i3 = in[3];\
    out[0] =    ((uint64_t) ctx->p_boxrowcol[ 0 ] [((i0 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i0 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i3 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i3 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i2 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i2 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i1 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i1 >> (7 * 8)) & 0xFF)]) + *(rkey + 0);\
    out[1] =    ((uint64_t) ctx->p_boxrowcol[ 0 ] [((i1 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i1 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i0 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i0 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i3 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i3 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i2 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i2 >> (7 * 8)) & 0xFF)]) + *(rkey + 1);\
    out[2] =    ((uint64_t) ctx->p_boxrowcol[ 0 ] [((i2 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i2 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i1 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i1 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i0 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i0 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i3 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i3 >> (7 * 8)) & 0xFF)]) + *(rkey + 2);\
    out[3] =  ((uint64_t) ctx->p_boxrowcol[ 0 ] [((i3 >> (0 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 1 ] [((i3 >> (1 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 2 ] [((i2 >> (2 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 3 ] [((i2 >> (3 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 4 ] [((i1 >> (4 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 5 ] [((i1 >> (5 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 6 ] [((i0 >> (6 * 8)) & 0xFF)]^\
                (uint64_t) ctx->p_boxrowcol[ 7 ] [((i0 >> (7 * 8)) & 0xFF)]) + *(rkey + 3);\
}\

#define BT_xor512(in, out, rkey) {\
        uint64_t i0 = in[0];\
        uint64_t i1 = in[1];\
        uint64_t i2 = in[2];\
        uint64_t i3 = in[3];\
        uint64_t i4 = in[4];\
        uint64_t i5 = in[5];\
        uint64_t i6 = in[6];\
        uint64_t i7 = in[7];\
        out[0] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i0 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i7 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i6 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i5 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i4 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i3 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i2 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i1 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 0);\
        out[1] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i1 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i0 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i7 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i6 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i5 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i4 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i3 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i2 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 1);\
        out[2] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i2 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i1 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i0 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i7 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i6 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i5 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i4 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i3 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 2);\
        out[3] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i3 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i2 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i1 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i0 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i7 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i6 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i5 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i4 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 3);\
        out[4] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i4 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i3 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i2 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i1 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i0 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i7 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i6 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i5 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 4);\
        out[5] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i5 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i4 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i3 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i2 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i1 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i0 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i7 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i6 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 5);\
        out[6] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i6 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i5 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i4 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i3 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i2 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i1 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i0 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i7 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 6);\
        out[7] =(uint64_t)ctx->p_boxrowcol[ 0 ] [( (i7 >> ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i6 >> ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i5 >> ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i4 >> ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i3 >> ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i2 >> ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i1 >> ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i0 >> ( 7 * 8) ) & 0xFF)] ^ *(rkey + 7);\
}\

#define BT_add512(in, out, rkey) { \
        uint64_t i0 = in[0];\
        uint64_t i1 = in[1];\
        uint64_t i2 = in[2];\
        uint64_t i3 = in[3];\
        uint64_t i4 = in[4];\
        uint64_t i5 = in[5];\
        uint64_t i6 = in[6];\
        uint64_t i7 = in[7];\
        out[0] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i0 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i7 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i6 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i5 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i4 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i3 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i2 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i1 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 0);\
        out[1] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i1 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i0 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i7 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i6 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i5 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i4 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i3 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i2 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 1);\
        out[2] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i2 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i1 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i0 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i7 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i6 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i5 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i4 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i3 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 2);\
        out[3] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i3 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i2 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i1 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i0 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i7 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i6 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i5 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i4 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 3);\
        out[4] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i4 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i3 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i2 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i1 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i0 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i7 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i6 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i5 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 4);\
        out[5] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i5 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i4 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i3 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i2 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i1 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i0 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i7 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i6 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 5);\
        out[6] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i6 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i5 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i4 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i3 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i2 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i1 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i0 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i7 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 6);\
        out[7] =((uint64_t)ctx->p_boxrowcol[ 0 ] [( (i7 >>  ( 0 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 1 ] [( (i6 >>  ( 1 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 2 ] [( (i5 >>  ( 2 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 3 ] [( (i4 >>  ( 3 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 4 ] [( (i3 >>  ( 4 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 5 ] [( (i2 >>  ( 5 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 6 ] [( (i1 >>  ( 6 * 8) ) & 0xFF)]^\
                (uint64_t)ctx->p_boxrowcol[ 7 ] [( (i0 >>  ( 7 * 8) ) & 0xFF)]) + *(rkey + 7);\
}\

const uint64_t subrowcol[8][256] = {
    {
        0xa832a829d77f9aa8, 0x4352432297d41143, 0x5f3e5fc2df80615f, 0x061e063014121806, 0x6bda6b7f670cb16b, 0x75bc758f2356c975, 0x6cc16c477519ad6c, 0x592059f2cb927959,
        0x71a871af3b4ad971, 0xdf84dfb6f8275bdf, 0x87a1874c35b22687, 0x95fb95dc59cc6e95, 0x174b17b872655c17, 0xf017f0d31aeae7f0, 0xd89fd88eea3247d8, 0x092d0948363f2409,
        0x6dc46d4f731ea96d, 0xf318f3cb10e3ebf3, 0x1d691de84e53741d, 0xcbc0cb16804b0bcb, 0xc9cac9068c4503c9, 0x4d644d52b3fe294d, 0x2c9c2c7de8c4b02c, 0xaf29af11c56a86af,
        0x798079ef0b72f979, 0xe047e0537a9aa7e0, 0x97f197cc55c26697, 0xfd2efdbb34c9d3fd, 0x6fce6f5f7f10a16f, 0x4b7a4b62a7ec314b, 0x454c451283c60945, 0x39dd39d596afe439,
        0x3ec63eed84baf83e, 0xdd8edda6f42953dd, 0xa315a371ed4eb6a3, 0x4f6e4f42bff0214f, 0xb45eb4c99f2beab4, 0xb654b6d99325e2b6, 0x9ac89aa47be1529a, 0x0e360e70242a380e,
        0x1f631ff8425d7c1f, 0xbf79bf91a51ac6bf, 0x154115a87e6b5415, 0xe142e15b7c9da3e1, 0x49704972abe23949, 0xd2bdd2ded6046fd2, 0x93e593ec4dde7693, 0xc6f9c67eae683fc6,
        0x92e092e44bd97292, 0x72a772b73143d572, 0x9edc9e8463fd429e, 0x61f8612f5b3a9961, 0xd1b2d1c6dc0d63d1, 0x63f2633f57349163, 0xfa35fa8326dccffa, 0xee71ee235eb09fee,
        0xf403f4f302f6f7f4, 0x197d19c8564f6419, 0xd5a6d5e6c41173d5, 0xad23ad01c9648ead, 0x582558facd957d58, 0xa40ea449ff5baaa4, 0xbb6dbbb1bd06d6bb, 0xa11fa161e140bea1,
        0xdc8bdcaef22e57dc, 0xf21df2c316e4eff2, 0x83b5836c2dae3683, 0x37eb37a5b285dc37, 0x4257422a91d31542, 0xe453e4736286b7e4, 0x7a8f7af7017bf57a, 0x32fa328dac9ec832,
        0x9cd69c946ff34a9c, 0xccdbcc2e925e17cc, 0xab3dab31dd7696ab, 0x4a7f4a6aa1eb354a, 0x8f898f0c058a068f, 0x6ecb6e577917a56e, 0x04140420181c1004, 0x27bb2725d2f59c27,
        0x2e962e6de4cab82e, 0xe75ce76b688fbbe7, 0xe24de2437694afe2, 0x5a2f5aeac19b755a, 0x96f496c453c56296, 0x164e16b074625816, 0x23af2305cae98c23, 0x2b872b45fad1ac2b,
        0xc2edc25eb6742fc2, 0x65ec650f43268965, 0x66e36617492f8566, 0x0f330f78222d3c0f, 0xbc76bc89af13cabc, 0xa937a921d1789ea9, 0x474647028fc80147, 0x415841329bda1941,
        0x34e434bdb88cd034, 0x4875487aade53d48, 0xfc2bfcb332ced7fc, 0xb751b7d19522e6b7, 0x6adf6a77610bb56a, 0x88928834179f1a88, 0xa50ba541f95caea5, 0x530253a2f7a45153,
        0x86a4864433b52286, 0xf93af99b2cd5c3f9, 0x5b2a5be2c79c715b, 0xdb90db96e03b4bdb, 0x38d838dd90a8e038, 0x7b8a7bff077cf17b, 0xc3e8c356b0732bc3, 0x1e661ef0445a781e,
        0x22aa220dccee8822, 0x33ff3385aa99cc33, 0x24b4243dd8fc9024, 0x2888285df0d8a028, 0x36ee36adb482d836, 0xc7fcc776a86f3bc7, 0xb240b2f98b39f2b2, 0x3bd73bc59aa1ec3b,
        0x8e8c8e04038d028e, 0x77b6779f2f58c177, 0xba68bab9bb01d2ba, 0xf506f5fb04f1f3f5, 0x144414a0786c5014, 0x9fd99f8c65fa469f, 0x0828084030382008, 0x551c5592e3b64955,
        0x9bcd9bac7de6569b, 0x4c614c5ab5f92d4c, 0xfe21fea33ec0dffe, 0x60fd60275d3d9d60, 0x5c315cdad5896d5c, 0xda95da9ee63c4fda, 0x187818c050486018, 0x4643460a89cf0546,
        0xcddecd26945913cd, 0x7d947dcf136ee97d, 0x21a52115c6e78421, 0xb04ab0e98737fab0, 0x3fc33fe582bdfc3f, 0x1b771bd85a416c1b, 0x8997893c11981e89, 0xff24ffab38c7dbff,
        0xeb60eb0b40ab8beb, 0x84ae84543fbb2a84, 0x69d0696f6b02b969, 0x3ad23acd9ca6e83a, 0x9dd39d9c69f44e9d, 0xd7acd7f6c81f7bd7, 0xd3b8d3d6d0036bd3, 0x70ad70a73d4ddd70,
        0x67e6671f4f288167, 0x405d403a9ddd1d40, 0xb55bb5c1992ceeb5, 0xde81debefe205fde, 0x5d345dd2d38e695d, 0x30f0309da090c030, 0x91ef91fc41d07e91, 0xb14fb1e18130feb1,
        0x788578e70d75fd78, 0x1155118866774411, 0x0105010806070401, 0xe556e57b6481b3e5, 0x0000000000000000, 0x68d568676d05bd68, 0x98c298b477ef5a98, 0xa01aa069e747baa0,
        0xc5f6c566a46133c5, 0x020a02100c0e0802, 0xa604a659f355a2a6, 0x74b974872551cd74, 0x2d992d75eec3b42d, 0x0b270b583a312c0b, 0xa210a279eb49b2a2, 0x76b37697295fc576,
        0xb345b3f18d3ef6b3, 0xbe7cbe99a31dc2be, 0xced1ce3e9e501fce, 0xbd73bd81a914cebd, 0xae2cae19c36d82ae, 0xe96ae91b4ca583e9, 0x8a988a241b91128a, 0x31f53195a697c431,
        0x1c6c1ce04854701c, 0xec7bec3352be97ec, 0xf112f1db1cede3f1, 0x99c799bc71e85e99, 0x94fe94d45fcb6a94, 0xaa38aa39db7192aa, 0xf609f6e30ef8fff6, 0x26be262dd4f29826,
        0x2f932f65e2cdbc2f, 0xef74ef2b58b79bef, 0xe86fe8134aa287e8, 0x8c868c140f830a8c, 0x35e135b5be8bd435, 0x030f03180a090c03, 0xd4a3d4eec21677d4, 0x7f9e7fdf1f60e17f,
        0xfb30fb8b20dbcbfb, 0x051105281e1b1405, 0xc1e2c146bc7d23c1, 0x5e3b5ecad987655e, 0x90ea90f447d77a90, 0x20a0201dc0e08020, 0x3dc93df58eb3f43d, 0x82b082642ba93282,
        0xf70cf7eb08fffbf7, 0xea65ea0346ac8fea, 0x0a220a503c36280a, 0x0d390d682e23340d, 0x7e9b7ed71967e57e, 0xf83ff8932ad2c7f8, 0x500d50bafdad5d50, 0x1a721ad05c46681a,
        0xc4f3c46ea26637c4, 0x071b073812151c07, 0x57165782efb84157, 0xb862b8a9b70fdab8, 0x3ccc3cfd88b4f03c, 0x62f7623751339562, 0xe348e34b7093abe3, 0xc8cfc80e8a4207c8,
        0xac26ac09cf638aac, 0x520752aaf1a35552, 0x64e9640745218d64, 0x1050108060704010, 0xd0b7d0ceda0a67d0, 0xd99ad986ec3543d9, 0x135f13986a794c13, 0x0c3c0c602824300c,
        0x125a12906c7e4812, 0x298d2955f6dfa429, 0x510851b2fbaa5951, 0xb967b9a1b108deb9, 0xcfd4cf3698571bcf, 0xd6a9d6fece187fd6, 0x73a273bf3744d173, 0x8d838d1c09840e8d,
        0x81bf817c21a03e81, 0x5419549ae5b14d54, 0xc0e7c04eba7a27c0, 0xed7eed3b54b993ed, 0x4e6b4e4ab9f7254e, 0x4449441a85c10d44, 0xa701a751f552a6a7, 0x2a822a4dfcd6a82a,
        0x85ab855c39bc2e85, 0x25b12535defb9425, 0xe659e6636e88bfe6, 0xcac5ca1e864c0fca, 0x7c917cc71569ed7c, 0x8b9d8b2c1d96168b, 0x5613568ae9bf4556, 0x80ba807427a73a80,
    },
    {
        0xd1ce3e9e501fcece, 0x6dbbb1bd06d6bbbb, 0x60eb0b40ab8bebeb, 0xe092e44bd9729292, 0x65ea0346ac8feaea, 0xc0cb16804b0bcbcb, 0x5f13986a794c1313, 0xe2c146bc7d23c1c1,
        0x6ae91b4ca583e9e9, 0xd23acd9ca6e83a3a, 0xa9d6fece187fd6d6, 0x40b2f98b39f2b2b2, 0xbdd2ded6046fd2d2, 0xea90f447d77a9090, 0x4b17b872655c1717, 0x3ff8932ad2c7f8f8,
        0x57422a91d3154242, 0x4115a87e6b541515, 0x13568ae9bf455656, 0x5eb4c99f2beab4b4, 0xec650f4326896565, 0x6c1ce04854701c1c, 0x928834179f1a8888, 0x52432297d4114343,
        0xf6c566a46133c5c5, 0x315cdad5896d5c5c, 0xee36adb482d83636, 0x68bab9bb01d2baba, 0x06f5fb04f1f3f5f5, 0x165782efb8415757, 0xe6671f4f28816767, 0x838d1c09840e8d8d,
        0xf53195a697c43131, 0x09f6e30ef8fff6f6, 0xe9640745218d6464, 0x2558facd957d5858, 0xdc9e8463fd429e9e, 0x03f4f302f6f7f4f4, 0xaa220dccee882222, 0x38aa39db7192aaaa,
        0xbc758f2356c97575, 0x330f78222d3c0f0f, 0x0a02100c0e080202, 0x4fb1e18130feb1b1, 0x84dfb6f8275bdfdf, 0xc46d4f731ea96d6d, 0xa273bf3744d17373, 0x644d52b3fe294d4d,
        0x917cc71569ed7c7c, 0xbe262dd4f2982626, 0x962e6de4cab82e2e, 0x0cf7eb08fffbf7f7, 0x2808403038200808, 0x345dd2d38e695d5d, 0x49441a85c10d4444, 0xc63eed84baf83e3e,
        0xd99f8c65fa469f9f, 0x4414a0786c501414, 0xcfc80e8a4207c8c8, 0x2cae19c36d82aeae, 0x19549ae5b14d5454, 0x5010806070401010, 0x9fd88eea3247d8d8, 0x76bc89af13cabcbc,
        0x721ad05c46681a1a, 0xda6b7f670cb16b6b, 0xd0696f6b02b96969, 0x18f3cb10e3ebf3f3, 0x73bd81a914cebdbd, 0xff3385aa99cc3333, 0x3dab31dd7696abab, 0x35fa8326dccffafa,
        0xb2d1c6dc0d63d1d1, 0xcd9bac7de6569b9b, 0xd568676d05bd6868, 0x6b4e4ab9f7254e4e, 0x4e16b07462581616, 0xfb95dc59cc6e9595, 0xef91fc41d07e9191, 0x71ee235eb09feeee,
        0x614c5ab5f92d4c4c, 0xf2633f5734916363, 0x8c8e04038d028e8e, 0x2a5be2c79c715b5b, 0xdbcc2e925e17cccc, 0xcc3cfd88b4f03c3c, 0x7d19c8564f641919, 0x1fa161e140bea1a1,
        0xbf817c21a03e8181, 0x704972abe2394949, 0x8a7bff077cf17b7b, 0x9ad986ec3543d9d9, 0xce6f5f7f10a16f6f, 0xeb37a5b285dc3737, 0xfd60275d3d9d6060, 0xc5ca1e864c0fcaca,
        0x5ce76b688fbbe7e7, 0x872b45fad1ac2b2b, 0x75487aade53d4848, 0x2efdbb34c9d3fdfd, 0xf496c453c5629696, 0x4c451283c6094545, 0x2bfcb332ced7fcfc, 0x5841329bda194141,
        0x5a12906c7e481212, 0x390d682e23340d0d, 0x8079ef0b72f97979, 0x56e57b6481b3e5e5, 0x97893c11981e8989, 0x868c140f830a8c8c, 0x48e34b7093abe3e3, 0xa0201dc0e0802020,
        0xf0309da090c03030, 0x8bdcaef22e57dcdc, 0x51b7d19522e6b7b7, 0xc16c477519ad6c6c, 0x7f4a6aa1eb354a4a, 0x5bb5c1992ceeb5b5, 0xc33fe582bdfc3f3f, 0xf197cc55c2669797,
        0xa3d4eec21677d4d4, 0xf762375133956262, 0x992d75eec3b42d2d, 0x1e06301412180606, 0x0ea449ff5baaa4a4, 0x0ba541f95caea5a5, 0xb5836c2dae368383, 0x3e5fc2df80615f5f,
        0x822a4dfcd6a82a2a, 0x95da9ee63c4fdada, 0xcac9068c4503c9c9, 0x0000000000000000, 0x9b7ed71967e57e7e, 0x10a279eb49b2a2a2, 0x1c5592e3b6495555, 0x79bf91a51ac6bfbf,
        0x5511886677441111, 0xa6d5e6c41173d5d5, 0xd69c946ff34a9c9c, 0xd4cf3698571bcfcf, 0x360e70242a380e0e, 0x220a503c36280a0a, 0xc93df58eb3f43d3d, 0x0851b2fbaa595151,
        0x947dcf136ee97d7d, 0xe593ec4dde769393, 0x771bd85a416c1b1b, 0x21fea33ec0dffefe, 0xf3c46ea26637c4c4, 0x4647028fc8014747, 0x2d0948363f240909, 0xa4864433b5228686,
        0x270b583a312c0b0b, 0x898f0c058a068f8f, 0xd39d9c69f44e9d9d, 0xdf6a77610bb56a6a, 0x1b073812151c0707, 0x67b9a1b108deb9b9, 0x4ab0e98737fab0b0, 0xc298b477ef5a9898,
        0x7818c05048601818, 0xfa328dac9ec83232, 0xa871af3b4ad97171, 0x7a4b62a7ec314b4b, 0x74ef2b58b79befef, 0xd73bc59aa1ec3b3b, 0xad70a73d4ddd7070, 0x1aa069e747baa0a0,
        0x53e4736286b7e4e4, 0x5d403a9ddd1d4040, 0x24ffab38c7dbffff, 0xe8c356b0732bc3c3, 0x37a921d1789ea9a9, 0x59e6636e88bfe6e6, 0x8578e70d75fd7878, 0x3af99b2cd5c3f9f9,
        0x9d8b2c1d96168b8b, 0x43460a89cf054646, 0xba807427a73a8080, 0x661ef0445a781e1e, 0xd838dd90a8e03838, 0x42e15b7c9da3e1e1, 0x62b8a9b70fdab8b8, 0x32a829d77f9aa8a8,
        0x47e0537a9aa7e0e0, 0x3c0c602824300c0c, 0xaf2305cae98c2323, 0xb37697295fc57676, 0x691de84e53741d1d, 0xb12535defb942525, 0xb4243dd8fc902424, 0x1105281e1b140505,
        0x12f1db1cede3f1f1, 0xcb6e577917a56e6e, 0xfe94d45fcb6a9494, 0x88285df0d8a02828, 0xc89aa47be1529a9a, 0xae84543fbb2a8484, 0x6fe8134aa287e8e8, 0x15a371ed4eb6a3a3,
        0x6e4f42bff0214f4f, 0xb6779f2f58c17777, 0xb8d3d6d0036bd3d3, 0xab855c39bc2e8585, 0x4de2437694afe2e2, 0x0752aaf1a3555252, 0x1df2c316e4eff2f2, 0xb082642ba9328282,
        0x0d50bafdad5d5050, 0x8f7af7017bf57a7a, 0x932f65e2cdbc2f2f, 0xb974872551cd7474, 0x0253a2f7a4515353, 0x45b3f18d3ef6b3b3, 0xf8612f5b3a996161, 0x29af11c56a86afaf,
        0xdd39d596afe43939, 0xe135b5be8bd43535, 0x81debefe205fdede, 0xdecd26945913cdcd, 0x631ff8425d7c1f1f, 0xc799bc71e85e9999, 0x26ac09cf638aacac, 0x23ad01c9648eadad,
        0xa772b73143d57272, 0x9c2c7de8c4b02c2c, 0x8edda6f42953dddd, 0xb7d0ceda0a67d0d0, 0xa1874c35b2268787, 0x7cbe99a31dc2bebe, 0x3b5ecad987655e5e, 0x04a659f355a2a6a6,
        0x7bec3352be97ecec, 0x140420181c100404, 0xf9c67eae683fc6c6, 0x0f03180a090c0303, 0xe434bdb88cd03434, 0x30fb8b20dbcbfbfb, 0x90db96e03b4bdbdb, 0x2059f2cb92795959,
        0x54b6d99325e2b6b6, 0xedc25eb6742fc2c2, 0x0501080607040101, 0x17f0d31aeae7f0f0, 0x2f5aeac19b755a5a, 0x7eed3b54b993eded, 0x01a751f552a6a7a7, 0xe36617492f856666,
        0xa52115c6e7842121, 0x9e7fdf1f60e17f7f, 0x988a241b91128a8a, 0xbb2725d2f59c2727, 0xfcc776a86f3bc7c7, 0xe7c04eba7a27c0c0, 0x8d2955f6dfa42929, 0xacd7f6c81f7bd7d7,
    },
    {
        0x93ec4dde769393e5, 0xd986ec3543d9d99a, 0x9aa47be1529a9ac8, 0xb5c1992ceeb5b55b, 0x98b477ef5a9898c2, 0x220dccee882222aa, 0x451283c60945454c, 0xfcb332ced7fcfc2b,
        0xbab9bb01d2baba68, 0x6a77610bb56a6adf, 0xdfb6f8275bdfdf84, 0x02100c0e0802020a, 0x9f8c65fa469f9fd9, 0xdcaef22e57dcdc8b, 0x51b2fbaa59515108, 0x59f2cb9279595920,
        0x4a6aa1eb354a4a7f, 0x17b872655c17174b, 0x2b45fad1ac2b2b87, 0xc25eb6742fc2c2ed, 0x94d45fcb6a9494fe, 0xf4f302f6f7f4f403, 0xbbb1bd06d6bbbb6d, 0xa371ed4eb6a3a315,
        0x62375133956262f7, 0xe4736286b7e4e453, 0x71af3b4ad97171a8, 0xd4eec21677d4d4a3, 0xcd26945913cdcdde, 0x70a73d4ddd7070ad, 0x16b074625816164e, 0xe15b7c9da3e1e142,
        0x4972abe239494970, 0x3cfd88b4f03c3ccc, 0xc04eba7a27c0c0e7, 0xd88eea3247d8d89f, 0x5cdad5896d5c5c31, 0x9bac7de6569b9bcd, 0xad01c9648eadad23, 0x855c39bc2e8585ab,
        0x53a2f7a451535302, 0xa161e140bea1a11f, 0x7af7017bf57a7a8f, 0xc80e8a4207c8c8cf, 0x2d75eec3b42d2d99, 0xe0537a9aa7e0e047, 0xd1c6dc0d63d1d1b2, 0x72b73143d57272a7,
        0xa659f355a2a6a604, 0x2c7de8c4b02c2c9c, 0xc46ea26637c4c4f3, 0xe34b7093abe3e348, 0x7697295fc57676b3, 0x78e70d75fd787885, 0xb7d19522e6b7b751, 0xb4c99f2beab4b45e,
        0x0948363f2409092d, 0x3bc59aa1ec3b3bd7, 0x0e70242a380e0e36, 0x41329bda19414158, 0x4c5ab5f92d4c4c61, 0xdebefe205fdede81, 0xb2f98b39f2b2b240, 0x90f447d77a9090ea,
        0x2535defb942525b1, 0xa541f95caea5a50b, 0xd7f6c81f7bd7d7ac, 0x03180a090c03030f, 0x1188667744111155, 0x0000000000000000, 0xc356b0732bc3c3e8, 0x2e6de4cab82e2e96,
        0x92e44bd9729292e0, 0xef2b58b79befef74, 0x4e4ab9f7254e4e6b, 0x12906c7e4812125a, 0x9d9c69f44e9d9dd3, 0x7dcf136ee97d7d94, 0xcb16804b0bcbcbc0, 0x35b5be8bd43535e1,
        0x1080607040101050, 0xd5e6c41173d5d5a6, 0x4f42bff0214f4f6e, 0x9e8463fd429e9edc, 0x4d52b3fe294d4d64, 0xa921d1789ea9a937, 0x5592e3b64955551c, 0xc67eae683fc6c6f9,
        0xd0ceda0a67d0d0b7, 0x7bff077cf17b7b8a, 0x18c0504860181878, 0x97cc55c2669797f1, 0xd3d6d0036bd3d3b8, 0x36adb482d83636ee, 0xe6636e88bfe6e659, 0x487aade53d484875,
        0x568ae9bf45565613, 0x817c21a03e8181bf, 0x8f0c058a068f8f89, 0x779f2f58c17777b6, 0xcc2e925e17ccccdb, 0x9c946ff34a9c9cd6, 0xb9a1b108deb9b967, 0xe2437694afe2e24d,
        0xac09cf638aacac26, 0xb8a9b70fdab8b862, 0x2f65e2cdbc2f2f93, 0x15a87e6b54151541, 0xa449ff5baaa4a40e, 0x7cc71569ed7c7c91, 0xda9ee63c4fdada95, 0x38dd90a8e03838d8,
        0x1ef0445a781e1e66, 0x0b583a312c0b0b27, 0x05281e1b14050511, 0xd6fece187fd6d6a9, 0x14a0786c50141444, 0x6e577917a56e6ecb, 0x6c477519ad6c6cc1, 0x7ed71967e57e7e9b,
        0x6617492f856666e3, 0xfdbb34c9d3fdfd2e, 0xb1e18130feb1b14f, 0xe57b6481b3e5e556, 0x60275d3d9d6060fd, 0xaf11c56a86afaf29, 0x5ecad987655e5e3b, 0x3385aa99cc3333ff,
        0x874c35b2268787a1, 0xc9068c4503c9c9ca, 0xf0d31aeae7f0f017, 0x5dd2d38e695d5d34, 0x6d4f731ea96d6dc4, 0x3fe582bdfc3f3fc3, 0x8834179f1a888892, 0x8d1c09840e8d8d83,
        0xc776a86f3bc7c7fc, 0xf7eb08fffbf7f70c, 0x1de84e53741d1d69, 0xe91b4ca583e9e96a, 0xec3352be97ecec7b, 0xed3b54b993eded7e, 0x807427a73a8080ba, 0x2955f6dfa429298d,
        0x2725d2f59c2727bb, 0xcf3698571bcfcfd4, 0x99bc71e85e9999c7, 0xa829d77f9aa8a832, 0x50bafdad5d50500d, 0x0f78222d3c0f0f33, 0x37a5b285dc3737eb, 0x243dd8fc902424b4,
        0x285df0d8a0282888, 0x309da090c03030f0, 0x95dc59cc6e9595fb, 0xd2ded6046fd2d2bd, 0x3eed84baf83e3ec6, 0x5be2c79c715b5b2a, 0x403a9ddd1d40405d, 0x836c2dae368383b5,
        0xb3f18d3ef6b3b345, 0x696f6b02b96969d0, 0x5782efb841575716, 0x1ff8425d7c1f1f63, 0x073812151c07071b, 0x1ce04854701c1c6c, 0x8a241b91128a8a98, 0xbc89af13cabcbc76,
        0x201dc0e0802020a0, 0xeb0b40ab8bebeb60, 0xce3e9e501fceced1, 0x8e04038d028e8e8c, 0xab31dd7696abab3d, 0xee235eb09feeee71, 0x3195a697c43131f5, 0xa279eb49b2a2a210,
        0x73bf3744d17373a2, 0xf99b2cd5c3f9f93a, 0xca1e864c0fcacac5, 0x3acd9ca6e83a3ad2, 0x1ad05c46681a1a72, 0xfb8b20dbcbfbfb30, 0x0d682e23340d0d39, 0xc146bc7d23c1c1e2,
        0xfea33ec0dffefe21, 0xfa8326dccffafa35, 0xf2c316e4eff2f21d, 0x6f5f7f10a16f6fce, 0xbd81a914cebdbd73, 0x96c453c5629696f4, 0xdda6f42953dddd8e, 0x432297d411434352,
        0x52aaf1a355525207, 0xb6d99325e2b6b654, 0x0840303820080828, 0xf3cb10e3ebf3f318, 0xae19c36d82aeae2c, 0xbe99a31dc2bebe7c, 0x19c8564f6419197d, 0x893c11981e898997,
        0x328dac9ec83232fa, 0x262dd4f2982626be, 0xb0e98737fab0b04a, 0xea0346ac8feaea65, 0x4b62a7ec314b4b7a, 0x640745218d6464e9, 0x84543fbb2a8484ae, 0x82642ba9328282b0,
        0x6b7f670cb16b6bda, 0xf5fb04f1f3f5f506, 0x79ef0b72f9797980, 0xbf91a51ac6bfbf79, 0x0108060704010105, 0x5fc2df80615f5f3e, 0x758f2356c97575bc, 0x633f5734916363f2,
        0x1bd85a416c1b1b77, 0x2305cae98c2323af, 0x3df58eb3f43d3dc9, 0x68676d05bd6868d5, 0x2a4dfcd6a82a2a82, 0x650f4326896565ec, 0xe8134aa287e8e86f, 0x91fc41d07e9191ef,
        0xf6e30ef8fff6f609, 0xffab38c7dbffff24, 0x13986a794c13135f, 0x58facd957d585825, 0xf1db1cede3f1f112, 0x47028fc801474746, 0x0a503c36280a0a22, 0x7fdf1f60e17f7f9e,
        0xc566a46133c5c5f6, 0xa751f552a6a7a701, 0xe76b688fbbe7e75c, 0x612f5b3a996161f8, 0x5aeac19b755a5a2f, 0x063014121806061e, 0x460a89cf05464643, 0x441a85c10d444449,
        0x422a91d315424257, 0x0420181c10040414, 0xa069e747baa0a01a, 0xdb96e03b4bdbdb90, 0x39d596afe43939dd, 0x864433b5228686a4, 0x549ae5b14d545419, 0xaa39db7192aaaa38,
        0x8c140f830a8c8c86, 0x34bdb88cd03434e4, 0x2115c6e7842121a5, 0x8b2c1d96168b8b9d, 0xf8932ad2c7f8f83f, 0x0c602824300c0c3c, 0x74872551cd7474b9, 0x671f4f28816767e6,
    },
    {
        0x676d05bd6868d568, 0x1c09840e8d8d838d, 0x1e864c0fcacac5ca, 0x52b3fe294d4d644d, 0xbf3744d17373a273, 0x62a7ec314b4b7a4b, 0x4ab9f7254e4e6b4e, 0x4dfcd6a82a2a822a,
        0xeec21677d4d4a3d4, 0xaaf1a35552520752, 0x2dd4f2982626be26, 0xf18d3ef6b3b345b3, 0x9ae5b14d54541954, 0xf0445a781e1e661e, 0xc8564f6419197d19, 0xf8425d7c1f1f631f,
        0x0dccee882222aa22, 0x180a090c03030f03, 0x0a89cf0546464346, 0xf58eb3f43d3dc93d, 0x75eec3b42d2d992d, 0x6aa1eb354a4a7f4a, 0xa2f7a45153530253, 0x6c2dae368383b583,
        0x986a794c13135f13, 0x241b91128a8a988a, 0xd19522e6b7b751b7, 0xe6c41173d5d5a6d5, 0x35defb942525b125, 0xef0b72f979798079, 0xfb04f1f3f5f506f5, 0x81a914cebdbd73bd,
        0xfacd957d58582558, 0x65e2cdbc2f2f932f, 0x682e23340d0d390d, 0x100c0e0802020a02, 0x3b54b993eded7eed, 0xb2fbaa5951510851, 0x8463fd429e9edc9e, 0x8866774411115511,
        0xc316e4eff2f21df2, 0xed84baf83e3ec63e, 0x92e3b64955551c55, 0xcad987655e5e3b5e, 0xc6dc0d63d1d1b2d1, 0xb074625816164e16, 0xfd88b4f03c3ccc3c, 0x17492f856666e366,
        0xa73d4ddd7070ad70, 0xd2d38e695d5d345d, 0xcb10e3ebf3f318f3, 0x1283c60945454c45, 0x3a9ddd1d40405d40, 0x2e925e17ccccdbcc, 0x134aa287e8e86fe8, 0xd45fcb6a9494fe94,
        0x8ae9bf4556561356, 0x4030382008082808, 0x3e9e501fceced1ce, 0xd05c46681a1a721a, 0xcd9ca6e83a3ad23a, 0xded6046fd2d2bdd2, 0x5b7c9da3e1e142e1, 0xb6f8275bdfdf84df,
        0xc1992ceeb5b55bb5, 0xdd90a8e03838d838, 0x577917a56e6ecb6e, 0x70242a380e0e360e, 0x7b6481b3e5e556e5, 0xf302f6f7f4f403f4, 0x9b2cd5c3f9f93af9, 0x4433b5228686a486,
        0x1b4ca583e9e96ae9, 0x42bff0214f4f6e4f, 0xfece187fd6d6a9d6, 0x5c39bc2e8585ab85, 0x05cae98c2323af23, 0x3698571bcfcfd4cf, 0x8dac9ec83232fa32, 0xbc71e85e9999c799,
        0x95a697c43131f531, 0xa0786c5014144414, 0x19c36d82aeae2cae, 0x235eb09feeee71ee, 0x0e8a4207c8c8cfc8, 0x7aade53d48487548, 0xd6d0036bd3d3b8d3, 0x9da090c03030f030,
        0x61e140bea1a11fa1, 0xe44bd9729292e092, 0x329bda1941415841, 0xe18130feb1b14fb1, 0xc050486018187818, 0x6ea26637c4c4f3c4, 0x7de8c4b02c2c9c2c, 0xaf3b4ad97171a871,
        0xb73143d57272a772, 0x1a85c10d44444944, 0xa87e6b5415154115, 0xbb34c9d3fdfd2efd, 0xa5b285dc3737eb37, 0x99a31dc2bebe7cbe, 0xc2df80615f5f3e5f, 0x39db7192aaaa38aa,
        0xac7de6569b9bcd9b, 0x34179f1a88889288, 0x8eea3247d8d89fd8, 0x31dd7696abab3dab, 0x3c11981e89899789, 0x946ff34a9c9cd69c, 0x8326dccffafa35fa, 0x275d3d9d6060fd60,
        0x0346ac8feaea65ea, 0x89af13cabcbc76bc, 0x375133956262f762, 0x602824300c0c3c0c, 0x3dd8fc902424b424, 0x59f355a2a6a604a6, 0x29d77f9aa8a832a8, 0x3352be97ecec7bec,
        0x1f4f28816767e667, 0x1dc0e0802020a020, 0x96e03b4bdbdb90db, 0xc71569ed7c7c917c, 0x5df0d8a028288828, 0xa6f42953dddd8edd, 0x09cf638aacac26ac, 0xe2c79c715b5b2a5b,
        0xbdb88cd03434e434, 0xd71967e57e7e9b7e, 0x8060704010105010, 0xdb1cede3f1f112f1, 0xff077cf17b7b8a7b, 0x0c058a068f8f898f, 0x3f5734916363f263, 0x69e747baa0a01aa0,
        0x281e1b1405051105, 0xa47be1529a9ac89a, 0x2297d41143435243, 0x9f2f58c17777b677, 0x15c6e7842121a521, 0x91a51ac6bfbf79bf, 0x25d2f59c2727bb27, 0x48363f2409092d09,
        0x56b0732bc3c3e8c3, 0x8c65fa469f9fd99f, 0xd99325e2b6b654b6, 0xf6c81f7bd7d7acd7, 0x55f6dfa429298d29, 0x5eb6742fc2c2edc2, 0x0b40ab8bebeb60eb, 0x4eba7a27c0c0e7c0,
        0x49ff5baaa4a40ea4, 0x2c1d96168b8b9d8b, 0x140f830a8c8c868c, 0xe84e53741d1d691d, 0x8b20dbcbfbfb30fb, 0xab38c7dbffff24ff, 0x46bc7d23c1c1e2c1, 0xf98b39f2b2b240b2,
        0xcc55c2669797f197, 0x6de4cab82e2e962e, 0x932ad2c7f8f83ff8, 0x0f4326896565ec65, 0xe30ef8fff6f609f6, 0x8f2356c97575bc75, 0x3812151c07071b07, 0x20181c1004041404,
        0x72abe23949497049, 0x85aa99cc3333ff33, 0x736286b7e4e453e4, 0x86ec3543d9d99ad9, 0xa1b108deb9b967b9, 0xceda0a67d0d0b7d0, 0x2a91d31542425742, 0x76a86f3bc7c7fcc7,
        0x477519ad6c6cc16c, 0xf447d77a9090ea90, 0x0000000000000000, 0x04038d028e8e8c8e, 0x5f7f10a16f6fce6f, 0xbafdad5d50500d50, 0x0806070401010501, 0x66a46133c5c5f6c5,
        0x9ee63c4fdada95da, 0x028fc80147474647, 0xe582bdfc3f3fc33f, 0x26945913cdcddecd, 0x6f6b02b96969d069, 0x79eb49b2a2a210a2, 0x437694afe2e24de2, 0xf7017bf57a7a8f7a,
        0x51f552a6a7a701a7, 0x7eae683fc6c6f9c6, 0xec4dde769393e593, 0x78222d3c0f0f330f, 0x503c36280a0a220a, 0x3014121806061e06, 0x636e88bfe6e659e6, 0x45fad1ac2b2b872b,
        0xc453c5629696f496, 0x71ed4eb6a3a315a3, 0xe04854701c1c6c1c, 0x11c56a86afaf29af, 0x77610bb56a6adf6a, 0x906c7e4812125a12, 0x543fbb2a8484ae84, 0xd596afe43939dd39,
        0x6b688fbbe7e75ce7, 0xe98737fab0b04ab0, 0x642ba9328282b082, 0xeb08fffbf7f70cf7, 0xa33ec0dffefe21fe, 0x9c69f44e9d9dd39d, 0x4c35b2268787a187, 0xdad5896d5c5c315c,
        0x7c21a03e8181bf81, 0xb5be8bd43535e135, 0xbefe205fdede81de, 0xc99f2beab4b45eb4, 0x41f95caea5a50ba5, 0xb332ced7fcfc2bfc, 0x7427a73a8080ba80, 0x2b58b79befef74ef,
        0x16804b0bcbcbc0cb, 0xb1bd06d6bbbb6dbb, 0x7f670cb16b6bda6b, 0x97295fc57676b376, 0xb9bb01d2baba68ba, 0xeac19b755a5a2f5a, 0xcf136ee97d7d947d, 0xe70d75fd78788578,
        0x583a312c0b0b270b, 0xdc59cc6e9595fb95, 0x4b7093abe3e348e3, 0x01c9648eadad23ad, 0x872551cd7474b974, 0xb477ef5a9898c298, 0xc59aa1ec3b3bd73b, 0xadb482d83636ee36,
        0x0745218d6464e964, 0x4f731ea96d6dc46d, 0xaef22e57dcdc8bdc, 0xd31aeae7f0f017f0, 0xf2cb927959592059, 0x21d1789ea9a937a9, 0x5ab5f92d4c4c614c, 0xb872655c17174b17,
        0xdf1f60e17f7f9e7f, 0xfc41d07e9191ef91, 0xa9b70fdab8b862b8, 0x068c4503c9c9cac9, 0x82efb84157571657, 0xd85a416c1b1b771b, 0x537a9aa7e0e047e0, 0x2f5b3a996161f861,
    },
    {
        0xd77f9aa8a832a829, 0x97d4114343524322, 0xdf80615f5f3e5fc2, 0x14121806061e0630, 0x670cb16b6bda6b7f, 0x2356c97575bc758f, 0x7519ad6c6cc16c47, 0xcb927959592059f2,
        0x3b4ad97171a871af, 0xf8275bdfdf84dfb6, 0x35b2268787a1874c, 0x59cc6e9595fb95dc, 0x72655c17174b17b8, 0x1aeae7f0f017f0d3, 0xea3247d8d89fd88e, 0x363f2409092d0948,
        0x731ea96d6dc46d4f, 0x10e3ebf3f318f3cb, 0x4e53741d1d691de8, 0x804b0bcbcbc0cb16, 0x8c4503c9c9cac906, 0xb3fe294d4d644d52, 0xe8c4b02c2c9c2c7d, 0xc56a86afaf29af11,
        0x0b72f979798079ef, 0x7a9aa7e0e047e053, 0x55c2669797f197cc, 0x34c9d3fdfd2efdbb, 0x7f10a16f6fce6f5f, 0xa7ec314b4b7a4b62, 0x83c60945454c4512, 0x96afe43939dd39d5,
        0x84baf83e3ec63eed, 0xf42953dddd8edda6, 0xed4eb6a3a315a371, 0xbff0214f4f6e4f42, 0x9f2beab4b45eb4c9, 0x9325e2b6b654b6d9, 0x7be1529a9ac89aa4, 0x242a380e0e360e70,
        0x425d7c1f1f631ff8, 0xa51ac6bfbf79bf91, 0x7e6b5415154115a8, 0x7c9da3e1e142e15b, 0xabe2394949704972, 0xd6046fd2d2bdd2de, 0x4dde769393e593ec, 0xae683fc6c6f9c67e,
        0x4bd9729292e092e4, 0x3143d57272a772b7, 0x63fd429e9edc9e84, 0x5b3a996161f8612f, 0xdc0d63d1d1b2d1c6, 0x5734916363f2633f, 0x26dccffafa35fa83, 0x5eb09feeee71ee23,
        0x02f6f7f4f403f4f3, 0x564f6419197d19c8, 0xc41173d5d5a6d5e6, 0xc9648eadad23ad01, 0xcd957d58582558fa, 0xff5baaa4a40ea449, 0xbd06d6bbbb6dbbb1, 0xe140bea1a11fa161,
        0xf22e57dcdc8bdcae, 0x16e4eff2f21df2c3, 0x2dae368383b5836c, 0xb285dc3737eb37a5, 0x91d315424257422a, 0x6286b7e4e453e473, 0x017bf57a7a8f7af7, 0xac9ec83232fa328d,
        0x6ff34a9c9cd69c94, 0x925e17ccccdbcc2e, 0xdd7696abab3dab31, 0xa1eb354a4a7f4a6a, 0x058a068f8f898f0c, 0x7917a56e6ecb6e57, 0x181c100404140420, 0xd2f59c2727bb2725,
        0xe4cab82e2e962e6d, 0x688fbbe7e75ce76b, 0x7694afe2e24de243, 0xc19b755a5a2f5aea, 0x53c5629696f496c4, 0x74625816164e16b0, 0xcae98c2323af2305, 0xfad1ac2b2b872b45,
        0xb6742fc2c2edc25e, 0x4326896565ec650f, 0x492f856666e36617, 0x222d3c0f0f330f78, 0xaf13cabcbc76bc89, 0xd1789ea9a937a921, 0x8fc8014747464702, 0x9bda194141584132,
        0xb88cd03434e434bd, 0xade53d484875487a, 0x32ced7fcfc2bfcb3, 0x9522e6b7b751b7d1, 0x610bb56a6adf6a77, 0x179f1a8888928834, 0xf95caea5a50ba541, 0xf7a45153530253a2,
        0x33b5228686a48644, 0x2cd5c3f9f93af99b, 0xc79c715b5b2a5be2, 0xe03b4bdbdb90db96, 0x90a8e03838d838dd, 0x077cf17b7b8a7bff, 0xb0732bc3c3e8c356, 0x445a781e1e661ef0,
        0xccee882222aa220d, 0xaa99cc3333ff3385, 0xd8fc902424b4243d, 0xf0d8a0282888285d, 0xb482d83636ee36ad, 0xa86f3bc7c7fcc776, 0x8b39f2b2b240b2f9, 0x9aa1ec3b3bd73bc5,
        0x038d028e8e8c8e04, 0x2f58c17777b6779f, 0xbb01d2baba68bab9, 0x04f1f3f5f506f5fb, 0x786c5014144414a0, 0x65fa469f9fd99f8c, 0x3038200808280840, 0xe3b64955551c5592,
        0x7de6569b9bcd9bac, 0xb5f92d4c4c614c5a, 0x3ec0dffefe21fea3, 0x5d3d9d6060fd6027, 0xd5896d5c5c315cda, 0xe63c4fdada95da9e, 0x50486018187818c0, 0x89cf05464643460a,
        0x945913cdcddecd26, 0x136ee97d7d947dcf, 0xc6e7842121a52115, 0x8737fab0b04ab0e9, 0x82bdfc3f3fc33fe5, 0x5a416c1b1b771bd8, 0x11981e898997893c, 0x38c7dbffff24ffab,
        0x40ab8bebeb60eb0b, 0x3fbb2a8484ae8454, 0x6b02b96969d0696f, 0x9ca6e83a3ad23acd, 0x69f44e9d9dd39d9c, 0xc81f7bd7d7acd7f6, 0xd0036bd3d3b8d3d6, 0x3d4ddd7070ad70a7,
        0x4f28816767e6671f, 0x9ddd1d40405d403a, 0x992ceeb5b55bb5c1, 0xfe205fdede81debe, 0xd38e695d5d345dd2, 0xa090c03030f0309d, 0x41d07e9191ef91fc, 0x8130feb1b14fb1e1,
        0x0d75fd78788578e7, 0x6677441111551188, 0x0607040101050108, 0x6481b3e5e556e57b, 0x0000000000000000, 0x6d05bd6868d56867, 0x77ef5a9898c298b4, 0xe747baa0a01aa069,
        0xa46133c5c5f6c566, 0x0c0e0802020a0210, 0xf355a2a6a604a659, 0x2551cd7474b97487, 0xeec3b42d2d992d75, 0x3a312c0b0b270b58, 0xeb49b2a2a210a279, 0x295fc57676b37697,
        0x8d3ef6b3b345b3f1, 0xa31dc2bebe7cbe99, 0x9e501fceced1ce3e, 0xa914cebdbd73bd81, 0xc36d82aeae2cae19, 0x4ca583e9e96ae91b, 0x1b91128a8a988a24, 0xa697c43131f53195,
        0x4854701c1c6c1ce0, 0x52be97ecec7bec33, 0x1cede3f1f112f1db, 0x71e85e9999c799bc, 0x5fcb6a9494fe94d4, 0xdb7192aaaa38aa39, 0x0ef8fff6f609f6e3, 0xd4f2982626be262d,
        0xe2cdbc2f2f932f65, 0x58b79befef74ef2b, 0x4aa287e8e86fe813, 0x0f830a8c8c868c14, 0xbe8bd43535e135b5, 0x0a090c03030f0318, 0xc21677d4d4a3d4ee, 0x1f60e17f7f9e7fdf,
        0x20dbcbfbfb30fb8b, 0x1e1b140505110528, 0xbc7d23c1c1e2c146, 0xd987655e5e3b5eca, 0x47d77a9090ea90f4, 0xc0e0802020a0201d, 0x8eb3f43d3dc93df5, 0x2ba9328282b08264,
        0x08fffbf7f70cf7eb, 0x46ac8feaea65ea03, 0x3c36280a0a220a50, 0x2e23340d0d390d68, 0x1967e57e7e9b7ed7, 0x2ad2c7f8f83ff893, 0xfdad5d50500d50ba, 0x5c46681a1a721ad0,
        0xa26637c4c4f3c46e, 0x12151c07071b0738, 0xefb8415757165782, 0xb70fdab8b862b8a9, 0x88b4f03c3ccc3cfd, 0x5133956262f76237, 0x7093abe3e348e34b, 0x8a4207c8c8cfc80e,
        0xcf638aacac26ac09, 0xf1a35552520752aa, 0x45218d6464e96407, 0x6070401010501080, 0xda0a67d0d0b7d0ce, 0xec3543d9d99ad986, 0x6a794c13135f1398, 0x2824300c0c3c0c60,
        0x6c7e4812125a1290, 0xf6dfa429298d2955, 0xfbaa5951510851b2, 0xb108deb9b967b9a1, 0x98571bcfcfd4cf36, 0xce187fd6d6a9d6fe, 0x3744d17373a273bf, 0x09840e8d8d838d1c,
        0x21a03e8181bf817c, 0xe5b14d545419549a, 0xba7a27c0c0e7c04e, 0x54b993eded7eed3b, 0xb9f7254e4e6b4e4a, 0x85c10d444449441a, 0xf552a6a7a701a751, 0xfcd6a82a2a822a4d,
        0x39bc2e8585ab855c, 0xdefb942525b12535, 0x6e88bfe6e659e663, 0x864c0fcacac5ca1e, 0x1569ed7c7c917cc7, 0x1d96168b8b9d8b2c, 0xe9bf45565613568a, 0x27a73a8080ba8074,
    },
    {
        0x501fceced1ce3e9e, 0x06d6bbbb6dbbb1bd, 0xab8bebeb60eb0b40, 0xd9729292e092e44b, 0xac8feaea65ea0346, 0x4b0bcbcbc0cb1680, 0x794c13135f13986a, 0x7d23c1c1e2c146bc,
        0xa583e9e96ae91b4c, 0xa6e83a3ad23acd9c, 0x187fd6d6a9d6fece, 0x39f2b2b240b2f98b, 0x046fd2d2bdd2ded6, 0xd77a9090ea90f447, 0x655c17174b17b872, 0xd2c7f8f83ff8932a,
        0xd315424257422a91, 0x6b5415154115a87e, 0xbf45565613568ae9, 0x2beab4b45eb4c99f, 0x26896565ec650f43, 0x54701c1c6c1ce048, 0x9f1a888892883417, 0xd411434352432297,
        0x6133c5c5f6c566a4, 0x896d5c5c315cdad5, 0x82d83636ee36adb4, 0x01d2baba68bab9bb, 0xf1f3f5f506f5fb04, 0xb8415757165782ef, 0x28816767e6671f4f, 0x840e8d8d838d1c09,
        0x97c43131f53195a6, 0xf8fff6f609f6e30e, 0x218d6464e9640745, 0x957d58582558facd, 0xfd429e9edc9e8463, 0xf6f7f4f403f4f302, 0xee882222aa220dcc, 0x7192aaaa38aa39db,
        0x56c97575bc758f23, 0x2d3c0f0f330f7822, 0x0e0802020a02100c, 0x30feb1b14fb1e181, 0x275bdfdf84dfb6f8, 0x1ea96d6dc46d4f73, 0x44d17373a273bf37, 0xfe294d4d644d52b3,
        0x69ed7c7c917cc715, 0xf2982626be262dd4, 0xcab82e2e962e6de4, 0xfffbf7f70cf7eb08, 0x3820080828084030, 0x8e695d5d345dd2d3, 0xc10d444449441a85, 0xbaf83e3ec63eed84,
        0xfa469f9fd99f8c65, 0x6c5014144414a078, 0x4207c8c8cfc80e8a, 0x6d82aeae2cae19c3, 0xb14d545419549ae5, 0x7040101050108060, 0x3247d8d89fd88eea, 0x13cabcbc76bc89af,
        0x46681a1a721ad05c, 0x0cb16b6bda6b7f67, 0x02b96969d0696f6b, 0xe3ebf3f318f3cb10, 0x14cebdbd73bd81a9, 0x99cc3333ff3385aa, 0x7696abab3dab31dd, 0xdccffafa35fa8326,
        0x0d63d1d1b2d1c6dc, 0xe6569b9bcd9bac7d, 0x05bd6868d568676d, 0xf7254e4e6b4e4ab9, 0x625816164e16b074, 0xcc6e9595fb95dc59, 0xd07e9191ef91fc41, 0xb09feeee71ee235e,
        0xf92d4c4c614c5ab5, 0x34916363f2633f57, 0x8d028e8e8c8e0403, 0x9c715b5b2a5be2c7, 0x5e17ccccdbcc2e92, 0xb4f03c3ccc3cfd88, 0x4f6419197d19c856, 0x40bea1a11fa161e1,
        0xa03e8181bf817c21, 0xe2394949704972ab, 0x7cf17b7b8a7bff07, 0x3543d9d99ad986ec, 0x10a16f6fce6f5f7f, 0x85dc3737eb37a5b2, 0x3d9d6060fd60275d, 0x4c0fcacac5ca1e86,
        0x8fbbe7e75ce76b68, 0xd1ac2b2b872b45fa, 0xe53d484875487aad, 0xc9d3fdfd2efdbb34, 0xc5629696f496c453, 0xc60945454c451283, 0xced7fcfc2bfcb332, 0xda1941415841329b,
        0x7e4812125a12906c, 0x23340d0d390d682e, 0x72f979798079ef0b, 0x81b3e5e556e57b64, 0x981e898997893c11, 0x830a8c8c868c140f, 0x93abe3e348e34b70, 0xe0802020a0201dc0,
        0x90c03030f0309da0, 0x2e57dcdc8bdcaef2, 0x22e6b7b751b7d195, 0x19ad6c6cc16c4775, 0xeb354a4a7f4a6aa1, 0x2ceeb5b55bb5c199, 0xbdfc3f3fc33fe582, 0xc2669797f197cc55,
        0x1677d4d4a3d4eec2, 0x33956262f7623751, 0xc3b42d2d992d75ee, 0x121806061e063014, 0x5baaa4a40ea449ff, 0x5caea5a50ba541f9, 0xae368383b5836c2d, 0x80615f5f3e5fc2df,
        0xd6a82a2a822a4dfc, 0x3c4fdada95da9ee6, 0x4503c9c9cac9068c, 0x0000000000000000, 0x67e57e7e9b7ed719, 0x49b2a2a210a279eb, 0xb64955551c5592e3, 0x1ac6bfbf79bf91a5,
        0x7744111155118866, 0x1173d5d5a6d5e6c4, 0xf34a9c9cd69c946f, 0x571bcfcfd4cf3698, 0x2a380e0e360e7024, 0x36280a0a220a503c, 0xb3f43d3dc93df58e, 0xaa5951510851b2fb,
        0x6ee97d7d947dcf13, 0xde769393e593ec4d, 0x416c1b1b771bd85a, 0xc0dffefe21fea33e, 0x6637c4c4f3c46ea2, 0xc80147474647028f, 0x3f2409092d094836, 0xb5228686a4864433,
        0x312c0b0b270b583a, 0x8a068f8f898f0c05, 0xf44e9d9dd39d9c69, 0x0bb56a6adf6a7761, 0x151c07071b073812, 0x08deb9b967b9a1b1, 0x37fab0b04ab0e987, 0xef5a9898c298b477,
        0x486018187818c050, 0x9ec83232fa328dac, 0x4ad97171a871af3b, 0xec314b4b7a4b62a7, 0xb79befef74ef2b58, 0xa1ec3b3bd73bc59a, 0x4ddd7070ad70a73d, 0x47baa0a01aa069e7,
        0x86b7e4e453e47362, 0xdd1d40405d403a9d, 0xc7dbffff24ffab38, 0x732bc3c3e8c356b0, 0x789ea9a937a921d1, 0x88bfe6e659e6636e, 0x75fd78788578e70d, 0xd5c3f9f93af99b2c,
        0x96168b8b9d8b2c1d, 0xcf05464643460a89, 0xa73a8080ba807427, 0x5a781e1e661ef044, 0xa8e03838d838dd90, 0x9da3e1e142e15b7c, 0x0fdab8b862b8a9b7, 0x7f9aa8a832a829d7,
        0x9aa7e0e047e0537a, 0x24300c0c3c0c6028, 0xe98c2323af2305ca, 0x5fc57676b3769729, 0x53741d1d691de84e, 0xfb942525b12535de, 0xfc902424b4243dd8, 0x1b1405051105281e,
        0xede3f1f112f1db1c, 0x17a56e6ecb6e5779, 0xcb6a9494fe94d45f, 0xd8a0282888285df0, 0xe1529a9ac89aa47b, 0xbb2a8484ae84543f, 0xa287e8e86fe8134a, 0x4eb6a3a315a371ed,
        0xf0214f4f6e4f42bf, 0x58c17777b6779f2f, 0x036bd3d3b8d3d6d0, 0xbc2e8585ab855c39, 0x94afe2e24de24376, 0xa35552520752aaf1, 0xe4eff2f21df2c316, 0xa9328282b082642b,
        0xad5d50500d50bafd, 0x7bf57a7a8f7af701, 0xcdbc2f2f932f65e2, 0x51cd7474b9748725, 0xa45153530253a2f7, 0x3ef6b3b345b3f18d, 0x3a996161f8612f5b, 0x6a86afaf29af11c5,
        0xafe43939dd39d596, 0x8bd43535e135b5be, 0x205fdede81debefe, 0x5913cdcddecd2694, 0x5d7c1f1f631ff842, 0xe85e9999c799bc71, 0x638aacac26ac09cf, 0x648eadad23ad01c9,
        0x43d57272a772b731, 0xc4b02c2c9c2c7de8, 0x2953dddd8edda6f4, 0x0a67d0d0b7d0ceda, 0xb2268787a1874c35, 0x1dc2bebe7cbe99a3, 0x87655e5e3b5ecad9, 0x55a2a6a604a659f3,
        0xbe97ecec7bec3352, 0x1c10040414042018, 0x683fc6c6f9c67eae, 0x090c03030f03180a, 0x8cd03434e434bdb8, 0xdbcbfbfb30fb8b20, 0x3b4bdbdb90db96e0, 0x927959592059f2cb,
        0x25e2b6b654b6d993, 0x742fc2c2edc25eb6, 0x0704010105010806, 0xeae7f0f017f0d31a, 0x9b755a5a2f5aeac1, 0xb993eded7eed3b54, 0x52a6a7a701a751f5, 0x2f856666e3661749,
        0xe7842121a52115c6, 0x60e17f7f9e7fdf1f, 0x91128a8a988a241b, 0xf59c2727bb2725d2, 0x6f3bc7c7fcc776a8, 0x7a27c0c0e7c04eba, 0xdfa429298d2955f6, 0x1f7bd7d7acd7f6c8,
    },
    {
        0x769393e593ec4dde, 0x43d9d99ad986ec35, 0x529a9ac89aa47be1, 0xeeb5b55bb5c1992c, 0x5a9898c298b477ef, 0x882222aa220dccee, 0x0945454c451283c6, 0xd7fcfc2bfcb332ce,
        0xd2baba68bab9bb01, 0xb56a6adf6a77610b, 0x5bdfdf84dfb6f827, 0x0802020a02100c0e, 0x469f9fd99f8c65fa, 0x57dcdc8bdcaef22e, 0x5951510851b2fbaa, 0x7959592059f2cb92,
        0x354a4a7f4a6aa1eb, 0x5c17174b17b87265, 0xac2b2b872b45fad1, 0x2fc2c2edc25eb674, 0x6a9494fe94d45fcb, 0xf7f4f403f4f302f6, 0xd6bbbb6dbbb1bd06, 0xb6a3a315a371ed4e,
        0x956262f762375133, 0xb7e4e453e4736286, 0xd97171a871af3b4a, 0x77d4d4a3d4eec216, 0x13cdcddecd269459, 0xdd7070ad70a73d4d, 0x5816164e16b07462, 0xa3e1e142e15b7c9d,
        0x394949704972abe2, 0xf03c3ccc3cfd88b4, 0x27c0c0e7c04eba7a, 0x47d8d89fd88eea32, 0x6d5c5c315cdad589, 0x569b9bcd9bac7de6, 0x8eadad23ad01c964, 0x2e8585ab855c39bc,
        0x5153530253a2f7a4, 0xbea1a11fa161e140, 0xf57a7a8f7af7017b, 0x07c8c8cfc80e8a42, 0xb42d2d992d75eec3, 0xa7e0e047e0537a9a, 0x63d1d1b2d1c6dc0d, 0xd57272a772b73143,
        0xa2a6a604a659f355, 0xb02c2c9c2c7de8c4, 0x37c4c4f3c46ea266, 0xabe3e348e34b7093, 0xc57676b37697295f, 0xfd78788578e70d75, 0xe6b7b751b7d19522, 0xeab4b45eb4c99f2b,
        0x2409092d0948363f, 0xec3b3bd73bc59aa1, 0x380e0e360e70242a, 0x1941415841329bda, 0x2d4c4c614c5ab5f9, 0x5fdede81debefe20, 0xf2b2b240b2f98b39, 0x7a9090ea90f447d7,
        0x942525b12535defb, 0xaea5a50ba541f95c, 0x7bd7d7acd7f6c81f, 0x0c03030f03180a09, 0x4411115511886677, 0x0000000000000000, 0x2bc3c3e8c356b073, 0xb82e2e962e6de4ca,
        0x729292e092e44bd9, 0x9befef74ef2b58b7, 0x254e4e6b4e4ab9f7, 0x4812125a12906c7e, 0x4e9d9dd39d9c69f4, 0xe97d7d947dcf136e, 0x0bcbcbc0cb16804b, 0xd43535e135b5be8b,
        0x4010105010806070, 0x73d5d5a6d5e6c411, 0x214f4f6e4f42bff0, 0x429e9edc9e8463fd, 0x294d4d644d52b3fe, 0x9ea9a937a921d178, 0x4955551c5592e3b6, 0x3fc6c6f9c67eae68,
        0x67d0d0b7d0ceda0a, 0xf17b7b8a7bff077c, 0x6018187818c05048, 0x669797f197cc55c2, 0x6bd3d3b8d3d6d003, 0xd83636ee36adb482, 0xbfe6e659e6636e88, 0x3d484875487aade5,
        0x45565613568ae9bf, 0x3e8181bf817c21a0, 0x068f8f898f0c058a, 0xc17777b6779f2f58, 0x17ccccdbcc2e925e, 0x4a9c9cd69c946ff3, 0xdeb9b967b9a1b108, 0xafe2e24de2437694,
        0x8aacac26ac09cf63, 0xdab8b862b8a9b70f, 0xbc2f2f932f65e2cd, 0x5415154115a87e6b, 0xaaa4a40ea449ff5b, 0xed7c7c917cc71569, 0x4fdada95da9ee63c, 0xe03838d838dd90a8,
        0x781e1e661ef0445a, 0x2c0b0b270b583a31, 0x1405051105281e1b, 0x7fd6d6a9d6fece18, 0x5014144414a0786c, 0xa56e6ecb6e577917, 0xad6c6cc16c477519, 0xe57e7e9b7ed71967,
        0x856666e36617492f, 0xd3fdfd2efdbb34c9, 0xfeb1b14fb1e18130, 0xb3e5e556e57b6481, 0x9d6060fd60275d3d, 0x86afaf29af11c56a, 0x655e5e3b5ecad987, 0xcc3333ff3385aa99,
        0x268787a1874c35b2, 0x03c9c9cac9068c45, 0xe7f0f017f0d31aea, 0x695d5d345dd2d38e, 0xa96d6dc46d4f731e, 0xfc3f3fc33fe582bd, 0x1a8888928834179f, 0x0e8d8d838d1c0984,
        0x3bc7c7fcc776a86f, 0xfbf7f70cf7eb08ff, 0x741d1d691de84e53, 0x83e9e96ae91b4ca5, 0x97ecec7bec3352be, 0x93eded7eed3b54b9, 0x3a8080ba807427a7, 0xa429298d2955f6df,
        0x9c2727bb2725d2f5, 0x1bcfcfd4cf369857, 0x5e9999c799bc71e8, 0x9aa8a832a829d77f, 0x5d50500d50bafdad, 0x3c0f0f330f78222d, 0xdc3737eb37a5b285, 0x902424b4243dd8fc,
        0xa0282888285df0d8, 0xc03030f0309da090, 0x6e9595fb95dc59cc, 0x6fd2d2bdd2ded604, 0xf83e3ec63eed84ba, 0x715b5b2a5be2c79c, 0x1d40405d403a9ddd, 0x368383b5836c2dae,
        0xf6b3b345b3f18d3e, 0xb96969d0696f6b02, 0x415757165782efb8, 0x7c1f1f631ff8425d, 0x1c07071b07381215, 0x701c1c6c1ce04854, 0x128a8a988a241b91, 0xcabcbc76bc89af13,
        0x802020a0201dc0e0, 0x8bebeb60eb0b40ab, 0x1fceced1ce3e9e50, 0x028e8e8c8e04038d, 0x96abab3dab31dd76, 0x9feeee71ee235eb0, 0xc43131f53195a697, 0xb2a2a210a279eb49,
        0xd17373a273bf3744, 0xc3f9f93af99b2cd5, 0x0fcacac5ca1e864c, 0xe83a3ad23acd9ca6, 0x681a1a721ad05c46, 0xcbfbfb30fb8b20db, 0x340d0d390d682e23, 0x23c1c1e2c146bc7d,
        0xdffefe21fea33ec0, 0xcffafa35fa8326dc, 0xeff2f21df2c316e4, 0xa16f6fce6f5f7f10, 0xcebdbd73bd81a914, 0x629696f496c453c5, 0x53dddd8edda6f429, 0x11434352432297d4,
        0x5552520752aaf1a3, 0xe2b6b654b6d99325, 0x2008082808403038, 0xebf3f318f3cb10e3, 0x82aeae2cae19c36d, 0xc2bebe7cbe99a31d, 0x6419197d19c8564f, 0x1e898997893c1198,
        0xc83232fa328dac9e, 0x982626be262dd4f2, 0xfab0b04ab0e98737, 0x8feaea65ea0346ac, 0x314b4b7a4b62a7ec, 0x8d6464e964074521, 0x2a8484ae84543fbb, 0x328282b082642ba9,
        0xb16b6bda6b7f670c, 0xf3f5f506f5fb04f1, 0xf979798079ef0b72, 0xc6bfbf79bf91a51a, 0x0401010501080607, 0x615f5f3e5fc2df80, 0xc97575bc758f2356, 0x916363f2633f5734,
        0x6c1b1b771bd85a41, 0x8c2323af2305cae9, 0xf43d3dc93df58eb3, 0xbd6868d568676d05, 0xa82a2a822a4dfcd6, 0x896565ec650f4326, 0x87e8e86fe8134aa2, 0x7e9191ef91fc41d0,
        0xfff6f609f6e30ef8, 0xdbffff24ffab38c7, 0x4c13135f13986a79, 0x7d58582558facd95, 0xe3f1f112f1db1ced, 0x0147474647028fc8, 0x280a0a220a503c36, 0xe17f7f9e7fdf1f60,
        0x33c5c5f6c566a461, 0xa6a7a701a751f552, 0xbbe7e75ce76b688f, 0x996161f8612f5b3a, 0x755a5a2f5aeac19b, 0x1806061e06301412, 0x05464643460a89cf, 0x0d444449441a85c1,
        0x15424257422a91d3, 0x100404140420181c, 0xbaa0a01aa069e747, 0x4bdbdb90db96e03b, 0xe43939dd39d596af, 0x228686a4864433b5, 0x4d545419549ae5b1, 0x92aaaa38aa39db71,
        0x0a8c8c868c140f83, 0xd03434e434bdb88c, 0x842121a52115c6e7, 0x168b8b9d8b2c1d96, 0xc7f8f83ff8932ad2, 0x300c0c3c0c602824, 0xcd7474b974872551, 0x816767e6671f4f28,
    },
    {
        0x6868d568676d05bd, 0x8d8d838d1c09840e, 0xcacac5ca1e864c0f, 0x4d4d644d52b3fe29, 0x7373a273bf3744d1, 0x4b4b7a4b62a7ec31, 0x4e4e6b4e4ab9f725, 0x2a2a822a4dfcd6a8,
        0xd4d4a3d4eec21677, 0x52520752aaf1a355, 0x2626be262dd4f298, 0xb3b345b3f18d3ef6, 0x545419549ae5b14d, 0x1e1e661ef0445a78, 0x19197d19c8564f64, 0x1f1f631ff8425d7c,
        0x2222aa220dccee88, 0x03030f03180a090c, 0x464643460a89cf05, 0x3d3dc93df58eb3f4, 0x2d2d992d75eec3b4, 0x4a4a7f4a6aa1eb35, 0x53530253a2f7a451, 0x8383b5836c2dae36,
        0x13135f13986a794c, 0x8a8a988a241b9112, 0xb7b751b7d19522e6, 0xd5d5a6d5e6c41173, 0x2525b12535defb94, 0x79798079ef0b72f9, 0xf5f506f5fb04f1f3, 0xbdbd73bd81a914ce,
        0x58582558facd957d, 0x2f2f932f65e2cdbc, 0x0d0d390d682e2334, 0x02020a02100c0e08, 0xeded7eed3b54b993, 0x51510851b2fbaa59, 0x9e9edc9e8463fd42, 0x1111551188667744,
        0xf2f21df2c316e4ef, 0x3e3ec63eed84baf8, 0x55551c5592e3b649, 0x5e5e3b5ecad98765, 0xd1d1b2d1c6dc0d63, 0x16164e16b0746258, 0x3c3ccc3cfd88b4f0, 0x6666e36617492f85,
        0x7070ad70a73d4ddd, 0x5d5d345dd2d38e69, 0xf3f318f3cb10e3eb, 0x45454c451283c609, 0x40405d403a9ddd1d, 0xccccdbcc2e925e17, 0xe8e86fe8134aa287, 0x9494fe94d45fcb6a,
        0x565613568ae9bf45, 0x0808280840303820, 0xceced1ce3e9e501f, 0x1a1a721ad05c4668, 0x3a3ad23acd9ca6e8, 0xd2d2bdd2ded6046f, 0xe1e142e15b7c9da3, 0xdfdf84dfb6f8275b,
        0xb5b55bb5c1992cee, 0x3838d838dd90a8e0, 0x6e6ecb6e577917a5, 0x0e0e360e70242a38, 0xe5e556e57b6481b3, 0xf4f403f4f302f6f7, 0xf9f93af99b2cd5c3, 0x8686a4864433b522,
        0xe9e96ae91b4ca583, 0x4f4f6e4f42bff021, 0xd6d6a9d6fece187f, 0x8585ab855c39bc2e, 0x2323af2305cae98c, 0xcfcfd4cf3698571b, 0x3232fa328dac9ec8, 0x9999c799bc71e85e,
        0x3131f53195a697c4, 0x14144414a0786c50, 0xaeae2cae19c36d82, 0xeeee71ee235eb09f, 0xc8c8cfc80e8a4207, 0x484875487aade53d, 0xd3d3b8d3d6d0036b, 0x3030f0309da090c0,
        0xa1a11fa161e140be, 0x9292e092e44bd972, 0x41415841329bda19, 0xb1b14fb1e18130fe, 0x18187818c0504860, 0xc4c4f3c46ea26637, 0x2c2c9c2c7de8c4b0, 0x7171a871af3b4ad9,
        0x7272a772b73143d5, 0x444449441a85c10d, 0x15154115a87e6b54, 0xfdfd2efdbb34c9d3, 0x3737eb37a5b285dc, 0xbebe7cbe99a31dc2, 0x5f5f3e5fc2df8061, 0xaaaa38aa39db7192,
        0x9b9bcd9bac7de656, 0x8888928834179f1a, 0xd8d89fd88eea3247, 0xabab3dab31dd7696, 0x898997893c11981e, 0x9c9cd69c946ff34a, 0xfafa35fa8326dccf, 0x6060fd60275d3d9d,
        0xeaea65ea0346ac8f, 0xbcbc76bc89af13ca, 0x6262f76237513395, 0x0c0c3c0c60282430, 0x2424b4243dd8fc90, 0xa6a604a659f355a2, 0xa8a832a829d77f9a, 0xecec7bec3352be97,
        0x6767e6671f4f2881, 0x2020a0201dc0e080, 0xdbdb90db96e03b4b, 0x7c7c917cc71569ed, 0x282888285df0d8a0, 0xdddd8edda6f42953, 0xacac26ac09cf638a, 0x5b5b2a5be2c79c71,
        0x3434e434bdb88cd0, 0x7e7e9b7ed71967e5, 0x1010501080607040, 0xf1f112f1db1cede3, 0x7b7b8a7bff077cf1, 0x8f8f898f0c058a06, 0x6363f2633f573491, 0xa0a01aa069e747ba,
        0x05051105281e1b14, 0x9a9ac89aa47be152, 0x434352432297d411, 0x7777b6779f2f58c1, 0x2121a52115c6e784, 0xbfbf79bf91a51ac6, 0x2727bb2725d2f59c, 0x09092d0948363f24,
        0xc3c3e8c356b0732b, 0x9f9fd99f8c65fa46, 0xb6b654b6d99325e2, 0xd7d7acd7f6c81f7b, 0x29298d2955f6dfa4, 0xc2c2edc25eb6742f, 0xebeb60eb0b40ab8b, 0xc0c0e7c04eba7a27,
        0xa4a40ea449ff5baa, 0x8b8b9d8b2c1d9616, 0x8c8c868c140f830a, 0x1d1d691de84e5374, 0xfbfb30fb8b20dbcb, 0xffff24ffab38c7db, 0xc1c1e2c146bc7d23, 0xb2b240b2f98b39f2,
        0x9797f197cc55c266, 0x2e2e962e6de4cab8, 0xf8f83ff8932ad2c7, 0x6565ec650f432689, 0xf6f609f6e30ef8ff, 0x7575bc758f2356c9, 0x07071b073812151c, 0x0404140420181c10,
        0x4949704972abe239, 0x3333ff3385aa99cc, 0xe4e453e4736286b7, 0xd9d99ad986ec3543, 0xb9b967b9a1b108de, 0xd0d0b7d0ceda0a67, 0x424257422a91d315, 0xc7c7fcc776a86f3b,
        0x6c6cc16c477519ad, 0x9090ea90f447d77a, 0x0000000000000000, 0x8e8e8c8e04038d02, 0x6f6fce6f5f7f10a1, 0x50500d50bafdad5d, 0x0101050108060704, 0xc5c5f6c566a46133,
        0xdada95da9ee63c4f, 0x47474647028fc801, 0x3f3fc33fe582bdfc, 0xcdcddecd26945913, 0x6969d0696f6b02b9, 0xa2a210a279eb49b2, 0xe2e24de2437694af, 0x7a7a8f7af7017bf5,
        0xa7a701a751f552a6, 0xc6c6f9c67eae683f, 0x9393e593ec4dde76, 0x0f0f330f78222d3c, 0x0a0a220a503c3628, 0x06061e0630141218, 0xe6e659e6636e88bf, 0x2b2b872b45fad1ac,
        0x9696f496c453c562, 0xa3a315a371ed4eb6, 0x1c1c6c1ce0485470, 0xafaf29af11c56a86, 0x6a6adf6a77610bb5, 0x12125a12906c7e48, 0x8484ae84543fbb2a, 0x3939dd39d596afe4,
        0xe7e75ce76b688fbb, 0xb0b04ab0e98737fa, 0x8282b082642ba932, 0xf7f70cf7eb08fffb, 0xfefe21fea33ec0df, 0x9d9dd39d9c69f44e, 0x8787a1874c35b226, 0x5c5c315cdad5896d,
        0x8181bf817c21a03e, 0x3535e135b5be8bd4, 0xdede81debefe205f, 0xb4b45eb4c99f2bea, 0xa5a50ba541f95cae, 0xfcfc2bfcb332ced7, 0x8080ba807427a73a, 0xefef74ef2b58b79b,
        0xcbcbc0cb16804b0b, 0xbbbb6dbbb1bd06d6, 0x6b6bda6b7f670cb1, 0x7676b37697295fc5, 0xbaba68bab9bb01d2, 0x5a5a2f5aeac19b75, 0x7d7d947dcf136ee9, 0x78788578e70d75fd,
        0x0b0b270b583a312c, 0x9595fb95dc59cc6e, 0xe3e348e34b7093ab, 0xadad23ad01c9648e, 0x7474b974872551cd, 0x9898c298b477ef5a, 0x3b3bd73bc59aa1ec, 0x3636ee36adb482d8,
        0x6464e9640745218d, 0x6d6dc46d4f731ea9, 0xdcdc8bdcaef22e57, 0xf0f017f0d31aeae7, 0x59592059f2cb9279, 0xa9a937a921d1789e, 0x4c4c614c5ab5f92d, 0x17174b17b872655c,
        0x7f7f9e7fdf1f60e1, 0x9191ef91fc41d07e, 0xb8b862b8a9b70fda, 0xc9c9cac9068c4503, 0x5757165782efb841, 0x1b1b771bd85a416c, 0xe0e047e0537a9aa7, 0x6161f8612f5b3a99,
    }
};

static const uint64_t subrowcol_dec[8][256] = {
    {
        0x7826942b9f5f8a9a, 0x210f43c934970c53, 0x5f028fdd9d0551b8, 0x14facd82b494c83b, 0x2b72ab886edd68c0, 0xa6a87e5bff19d9b4, 0xa29ae571db6443ea, 0x039b2c911be8e5b6,
        0xd9275dcb5fd32cc6, 0x10c856a890e95265, 0x7d96e085b27ab85d, 0x31c71561a47e5e36, 0x74702455f3d83978, 0xe8e048aafbad72f0, 0x9b39db4437e03460, 0x75f2cbd1fa8091e1,
        0x1ab5bee9caa336f6, 0x8395a6b8eff34fb9, 0x64b872fd63316b1d, 0xe1068c7aba0ff3d5, 0xeecb1095cd60a581, 0xbc1dc0b235baef42, 0xf04c355623be0929, 0xb252b3d94b8d118f,
        0x18ac7dfcd8137bd9, 0xbbb477090a2f90aa, 0x8625d216c2d67d7e, 0x66a1b1e871812632, 0x6f4775383023a717, 0x92df1f947642b545, 0xe962a72ef2f5da69, 0x8bf18deca7096605,
        0xc86de4e7c662d63a, 0xaafece25939e6a56, 0x5c99a34c86edb40e, 0x52d6d027f8da4ac3, 0x6b75ee12145e3d49, 0x54fd8818ce179db2, 0xa3180af5d23ceb73, 0xbe0403a7270aa26d,
        0xfe03463d5d89f7e4, 0xf1cedad22ae6a1b0, 0xd143769f1729057a, 0xc7a07808b10d806e, 0xfc1a85284f39bacb, 0xa4b1bd4eeda9949b, 0x0bff07c55312cc0a, 0xef49ff11c4380d18,
        0xc392e32295701a30, 0x7f8f2390a0caf572, 0x62932ac255fcbc6c, 0xc9ef0b63cf3a7ea3, 0xf9aaf186621c880c, 0x818c65adfd430296, 0x325c39f0bf96bb80, 0x0c56b07e6c87b3e2,
        0x4bf8425f29919983, 0xb5fb046274186e67, 0x462c1da54c4e82f8, 0x90c6dc8164f2f86a, 0xf8281e026b442095, 0x6af701961d0695d0, 0x5766a489d5ff7804, 0xf3d719c73856ec9f,
        0xad57799eac0b15be, 0x1b37516dc3fb9e6f, 0xc009cfb38e98ff86, 0x9576a82f49d7caad, 0xe6af3bc1859a8c3d, 0x208dac4d3dcfa4ca, 0x8ddad5d391c4b174, 0x8e41f9428a2c54c2,
        0x6cdc59a92bcb42a1, 0xe53417509e72698b, 0xd0c1991b1e71ade3, 0x8217493ce6abe720, 0xd4f302313a0c37bd, 0x5e806059945df921, 0x73d993eecc4d4690, 0xf5fc41f80e9b3bee,
        0x13537a398b01b7d3, 0x53543fa3f182e25a, 0x2d59f3b75810bfb1, 0x35f58e4b8003c468, 0x886aa17dbce183b3, 0x4c51f5e41604e66b, 0x98a2f7d52c08d1d6, 0xa101c9e0c08ca65c,
        0x4007459a7a835589, 0xcc5f7fcde21f4c64, 0xa965e2b488768fe0, 0x12d195bd82591f4a, 0x2f4030a24aa0f29e, 0x56e44b0ddca7d09d, 0x914433056daa50f3, 0x37ec4d5e92b38947,
        0xe31f4f6fa8bfbefa, 0x50cf1332ea6a07ec, 0x6d5eb62d2293ea38, 0x09e6c4d041a28125, 0x8fc316c68374fc5b, 0x421e868f683318a6, 0xe08463feb3575b4c, 0x3821d1b1e5dcdf13,
        0xed503c04d6884037, 0xd35ab58a05994855, 0x976f6b3a5b678782, 0x6ec59abc397b0f8e, 0x5929d7e2abc886c9, 0xa53352cae4f13c02, 0x89e84ef9b5b92b2a, 0x1761e113af7c2d8d,
        0x28e9871975358d76, 0xdc97296572f61e01, 0x67235e6c78d98eab, 0x3d91a51fc8f9edd4, 0x68eec2830fb6d8ff, 0xfbb3329370acc523, 0x062b583f36cdd771, 0x15782206bdcc60a2,
        0x16e30e97a6248514, 0x79a47baf96072203, 0xf7e582ed1c2b76c1, 0xde8eea706046532e, 0xaf4eba8bbebb5891, 0x08642b5448fa29bc, 0x24bf376719b23e94, 0x231680dc2627417c,
        0x0dd45ffa65df1b7b, 0x1d1c0952f536491e, 0xff81a9b954d15f7d, 0x992018512550794f, 0x71c050fbdefd0bbf, 0xc18b203787c0571f, 0x253dd8e310ea960d, 0xeb7b643be0459746,
        0x0219c31512b04d2f, 0xc43b5499aae565d8, 0xeaf98bbfe91d3fdf, 0x3a3812a4f76c923c, 0x4dd31a601f5c4ef2, 0xa8e70d30812e2779, 0x800e8a29f41baa0f, 0x1c9ee6d6fc6ee187,
        0x5d1b4cc88fb51c97, 0x610806534e1459da, 0xf255f643310e4406, 0xd2d85a0e0cc1e0cc, 0x0182ef840958a899, 0x7e0dcc14a9925deb, 0x653a9d796a69c384, 0x4e4836f104b4ab44,
        0x4fcad9750dec03dd, 0xcddd9049eb47e4fd, 0x0e4f736b7e37fecd, 0x4185aa1e73dbfd10, 0x725b7c6ac515ee09, 0x8a736268ae51ce9c, 0xc5b9bb1da3bdcd41, 0x7bbdb8ba84b76f2c,
        0xdabc715a443bc970, 0xe29da0eba1e71663, 0x935df0107f1a1ddc, 0x608ae9d7474cf143, 0xd571edb533549f24, 0xa0832664c9d40ec5, 0xfd986aac46611252, 0x4435deb05efecfd7,
        0x0000000000000000, 0x2cdb1c3351481728, 0x94f447ab408f6234, 0x45b7313457a6674e, 0xb82f5b9811c7751c, 0x8c583a57989c19ed, 0xdd15c6e17baeb698, 0x696c2d0706ee7066,
        0x3f88660ada49a0fb, 0xf47eae7c07c39377, 0x05b074ae2d2532c7, 0xb3d05c5d42d5b916, 0x39a33e35ec84778a, 0x0fcd9cef776f5654, 0xacd5961aa553bd27, 0x5b3014f7b978cbe6,
        0x347761cf895b6cf1, 0xc622978cb85528f7, 0xb7e2c77766a82348, 0x77eb08c4e830dcce, 0xb9adb41c189fdd85, 0x114ab92c99b1fafc, 0x26a6f4720b0273bb, 0x1e8725c3eedeaca8,
        0x2af0440c6785c059, 0x04329b2a247d9a5e, 0xd7682ea021e4d20b, 0x7c140f01bb2210c4, 0x96ed84be523f2f1b, 0xca7427f2d4d29b15, 0x47aef22145162a61, 0xa72a91dff641712d,
        0x5ab2fb73b020637f, 0xcbf6c876dd8a338c, 0x6311c5465ca414f5, 0x07a9b7bb3f957fe8, 0xe72dd4458cc224a4, 0x9d12837b012de311, 0x843c1103d0663051, 0x0a7de8415a4a6493,
        0xd6eac12428bc7a92, 0x9c906cff08754b88, 0x7042bf7fd7a5a326, 0xbd9f2f363ce247db, 0xb66028f36ff08bd1, 0x192e9278d14bd340, 0x9f0b406e139dae3e, 0x1f05ca47e7860431,
        0x85befe87d93e98c8, 0x439c690b616bb03f, 0xba36988d03773833, 0x87a73d92cb8ed5e7, 0xaecc550fb7e3f008, 0xc2100ca69c28b2a9, 0x9abb34c03eb89cf9, 0x49e1814a3b21d4ac,
        0xecd2d380dfd0e8ae, 0x296b689d7c6d25ef, 0x3c134a9bc1a1454d, 0xcfc4535cf9f7a9d2, 0x557f679cc74f352b, 0xb479ebe67d40c6fe, 0xf6676d691573de58, 0x9e89afea1ac506a7,
        0xd8a5b24f568b845f, 0x48636ece32797c35, 0xdf0c05f4691efbb7, 0xe4b6f8d4972ac112, 0xfa31dd1779f46dba, 0xbf86ec232e520af4, 0x3e0a898ed3110862, 0x7a3f573e8defc7b5,
        0x27241bf6025adb22, 0x58ab3866a2902e50, 0x3bbafd20fe343aa5, 0x3045fae5ad26f6af, 0x2ec2df2643f85a07, 0x22946f582f7fe9e5, 0x366ea2da9beb21de, 0x4a7aaddb20c9311a,
        0xb1c99f485065f439, 0xb04b70cc593d5ca0, 0xab7c21a19ac6c2cf, 0x33ded674b6ce1319, 0xce46bcd8f0af014b, 0xdb3e9ede4d6361e9, 0x7669e740e1687457, 0x514dfcb6e332af75,
    },
    {
        0x1f4f6fa8bfbefae3, 0xf0440c6785c0592a, 0x1dc0b235baef42bc, 0x22978cb85528f7c6, 0xcedad22ae6a1b0f1, 0x180af5d23ceb73a3, 0x946f582f7fe9e522, 0xe44b0ddca7d09d56,
        0x906cff08754b889c, 0x9f2f363ce247dbbd, 0xa1b1e87181263266, 0x21d1b1e5dcdf1338, 0x31dd1779f46dbafa, 0x4b70cc593d5ca0b0, 0xd719c73856ec9ff3, 0x8725c3eedeaca81e,
        0x71edb533549f24d5, 0x12837b012de3119d, 0x3dd8e310ea960d25, 0x29d7e2abc886c959, 0xb477090a2f90aabb, 0x45fae5ad26f6af30, 0x9ee6d6fc6ee1871c, 0xbefe87d93e98c885,
        0xe30e97a624851416, 0xd6d027f8da4ac352, 0xcc550fb7e3f008ae, 0x5ab58a05994855d3, 0x806059945df9215e, 0x82ef840958a89901, 0x4ab92c99b1fafc11, 0x281e026b442095f8,
        0x62a72ef2f5da69e9, 0x8b203787c0571fc1, 0x4f736b7e37fecd0e, 0xab3866a2902e5058, 0x6ea2da9beb21de36, 0xf447ab408f623494, 0x235e6c78d98eab67, 0x11c5465ca414f563,
        0xd31a601f5c4ef24d, 0xa2f7d52c08d1d698, 0x85aa1e73dbfd1041, 0xdc59a92bcb42a16c, 0x59f3b75810bfb12d, 0xe2c77766a82348b7, 0xb9bb1da3bdcd41c5, 0x96e085b27ab85d7d,
        0x99a34c86edb40e5c, 0x66a489d5ff780457, 0x95a6b8eff34fb983, 0x7f679cc74f352b55, 0x7de8415a4a64930a, 0x9b2c911be8e5b603, 0x4836f104b4ab444e, 0xdb1c33514817282c,
        0x15c6e17baeb698dd, 0xed84be523f2f1b96, 0xe1814a3b21d4ac49, 0x503c04d6884037ed, 0x4c355623be0929f0, 0x3b5499aae565d8c4, 0x0a898ed31108623e, 0xb074ae2d2532c705,
        0x028fdd9d0551b85f, 0xf58e4b8003c46835, 0x3352cae4f13c02a5, 0x6c2d0706ee706669, 0x7c21a19ac6c2cfab, 0x19c31512b04d2f02, 0xa6f4720b0273bb26, 0x05ca47e78604311f,
        0x46bcd8f0af014bce, 0x1e868f683318a642, 0x5c39f0bf96bb8032, 0x79ebe67d40c6feb4, 0xff07c55312cc0a0b, 0xaef22145162a6147, 0xc1991b1e71ade3d0, 0xded674b6ce131933,
        0x7aaddb20c9311a4a, 0x4dfcb6e332af7551, 0x6de4e7c662d63ac8, 0xbf376719b23e9424, 0x07459a7a83558940, 0xac7dfcd8137bd918, 0xdf1f947642b54592, 0x17493ce6abe72082,
        0xfc41f80e9b3beef5, 0xe70d30812e2779a8, 0xd993eecc4d469073, 0x65e2b488768fe0a9, 0xd2d380dfd0e8aeec, 0xe6c4d041a2812509, 0x068c7aba0ff3d5e1, 0x51f5e41604e66b4c,
        0x41f9428a2c54c28e, 0x537a398b01b7d313, 0x782206bdcc60a215, 0x89afea1ac506a79e, 0x8ae9d7474cf14360, 0xf6c876dd8a338ccb, 0x43769f1729057ad1, 0x8dac4d3dcfa4ca20,
        0xb7313457a6674e45, 0x2018512550794f99, 0xbb34c03eb89cf99a, 0xbafd20fe343aa53b, 0x03463d5d89f7e4fe, 0x42bf7fd7a5a32670, 0x3f573e8defc7b57a, 0xadb41c189fdd85b9,
        0xcad9750dec03dd4f, 0x0f43c934970c5321, 0x2f5b9811c7751cb8, 0xd85a0e0cc1e0ccd2, 0xe048aafbad72f0e8, 0xf18deca70966058b, 0xdd9049eb47e4fdcd, 0xa87e5bff19d9b4a6,
        0x5df0107f1a1ddc93, 0xd195bd82591f4a12, 0x0c05f4691efbb7df, 0x8463feb3575b4ce0, 0x55f643310e4406f2, 0xb6f8d4972ac112e4, 0x4030a24aa0f29e2f, 0xfd8818ce179db254,
        0x3c1103d066305184, 0x682ea021e4d20bd7, 0x81a9b954d15f7dff, 0x275dcb5fd32cc6d9, 0xfacd82b494c83b14, 0x4433056daa50f391, 0xe9871975358d7628, 0xeac12428bc7a92d6,
        0x1a85284f39bacbfc, 0xf8425f299199834b, 0x676d691573de58f6, 0xd05c5d42d5b916b3, 0x8eea706046532ede, 0xfb046274186e67b5, 0x134a9bc1a1454d3c, 0x57799eac0b15bead,
        0x241bf6025adb2227, 0x72ab886edd68c02b, 0x9ae571db6443eaa2, 0xc050fbdefd0bbf71, 0xa5b24f568b845fd8, 0xe84ef9b5b92b2a89, 0x6f6b3a5b67878297, 0xc6dc8164f2f86a90,
        0x7eae7c07c39377f4, 0x5eb62d2293ea386d, 0x8c65adfd43029681, 0x2dd4458cc224a4e7, 0xfece25939e6a56aa, 0xcd9cef776f56540f, 0xa33e35ec84778a39, 0xc2df2643f85a072e,
        0xbc715a443bc970da, 0xa07808b10d806ec7, 0x36988d03773833ba, 0x1680dc2627417c23, 0xcb1095cd60a581ee, 0xbdb8ba84b76f2c7b, 0x702455f3d8397874, 0x35deb05efecfd744,
        0x8f2390a0caf5727f, 0xb1bd4eeda9949ba4, 0x39db4437e034609b, 0xe582ed1c2b76c1f7, 0xc4535cf9f7a9d2cf, 0xb2fb73b020637f5a, 0x583a57989c19ed8c, 0x25d216c2d67d7e86,
        0x0806534e1459da61, 0x6b689d7c6d25ef29, 0x0dcc14a9925deb7e, 0xc99f485065f439b1, 0xa9b7bb3f957fe807, 0x2a91dff641712da7, 0x1c0952f536491e1d, 0x75ee12145e3d496b,
        0xf98bbfe91d3fdfea, 0x92e32295701a30c3, 0x3e9ede4d6361e9db, 0x76a82f49d7caad95, 0x9da0eba1e71663e2, 0x09cfb38e98ff86c0, 0x9c690b616bb03f43, 0xdad5d391c4b1748d,
        0x3812a4f76c923c3a, 0x5f7fcde21f4c64cc, 0x6aa17dbce183b388, 0xeec2830fb6d8ff68, 0x736268ae51ce9c8a, 0xa47baf9607220379, 0x543fa3f182e25a53, 0x4eba8bbebb5891af,
        0x2e9278d14bd34019, 0x69e740e168745776, 0x37516dc3fb9e6f1b, 0xb3329370acc523fb, 0x3a9d796a69c38465, 0x7761cf895b6cf134, 0x0000000000000000, 0x88660ada49a0fb3f,
        0xb5bee9caa336f61a, 0x5b7c6ac515ee0972, 0x52b3d94b8d118fb2, 0x329b2a247d9a5e04, 0x0e8a29f41baa0f80, 0x642b5448fa29bc08, 0x7b643be0459746eb, 0xd45ffa65df1b7b0d,
        0xeb08c4e830dcce77, 0xf2cbd1fa8091e175, 0xf302313a0c37bdd4, 0x91a51fc8f9edd43d, 0xef0b63cf3a7ea3c9, 0xc316c68374fc5b8f, 0x01c9e0c08ca65ca1, 0x3417509e72698be5,
        0x4775383023a7176f, 0x636ece32797c3548, 0x1b4cc88fb51c975d, 0x140f01bb2210c47c, 0x7427f2d4d29b15ca, 0xa73d92cb8ed5e787, 0xc71561a47e5e3631, 0xaaf186621c880cf9,
        0x6028f36ff08bd1b6, 0x97296572f61e01dc, 0xc59abc397b0f8e6e, 0xec4d5e92b3894737, 0xb872fd63316b1d64, 0xaf3bc1859a8c3de6, 0x0403a7270aa26dbe, 0x26942b9f5f8a9a78,
        0x86ec232e520af4bf, 0x49ff11c4380d18ef, 0xf701961d0695d06a, 0x56b07e6c87b3e20c, 0xd5961aa553bd27ac, 0x61e113af7c2d8d17, 0x100ca69c28b2a9c2, 0xcf1332ea6a07ec50,
        0xc856a890e9526510, 0x2b583f36cdd77106, 0x932ac255fcbc6c62, 0x0b406e139dae3e9f, 0x832664c9d40ec5a0, 0x3014f7b978cbe65b, 0x2c1da54c4e82f846, 0x986aac46611252fd,
    },
    {
        0x679cc74f352b557f, 0x376719b23e9424bf, 0xcc14a9925deb7e0d, 0xb07e6c87b3e20c56, 0xa17dbce183b3886a, 0xee12145e3d496b75, 0x406e139dae3e9f0b, 0x942b9f5f8a9a7826,
        0xb24f568b845fd8a5, 0xdf2643f85a072ec2, 0x8c7aba0ff3d5e106, 0x0b63cf3a7ea3c9ef, 0x12a4f76c923c3a38, 0x8bbfe91d3fdfeaf9, 0x9278d14bd340192e, 0xca47e78604311f05,
        0x07c55312cc0a0bff, 0xcfb38e98ff86c009, 0x991b1e71ade3d0c1, 0x16c68374fc5b8fc3, 0x39f0bf96bb80325c, 0x3d92cb8ed5e787a7, 0xac4d3dcfa4ca208d, 0xfae5ad26f6af3045,
        0x63feb3575b4ce084, 0x28f36ff08bd1b660, 0xc6e17baeb698dd15, 0x84be523f2f1b96ed, 0x3c04d6884037ed50, 0xce25939e6a56aafe, 0xa34c86edb40e5c99, 0xebe67d40c6feb479,
        0x27f2d4d29b15ca74, 0x6d691573de58f667, 0x329370acc523fbb3, 0x2c911be8e5b6039b, 0x871975358d7628e9, 0x550fb7e3f008aecc, 0x7e5bff19d9b4a6a8, 0xf8d4972ac112e4b6,
        0xd1b1e5dcdf133821, 0xfcb6e332af75514d, 0x1e026b442095f828, 0x1f947642b54592df, 0x5e6c78d98eab6723, 0x17509e72698be534, 0x2ac255fcbc6c6293, 0x95bd82591f4a12d1,
        0x799eac0b15bead57, 0xf0107f1a1ddc935d, 0xd674b6ce131933de, 0xf5e41604e66b4c51, 0x8818ce179db254fd, 0x03a7270aa26dbe04, 0x1c33514817282cdb, 0x2f363ce247dbbd9f,
        0xa72ef2f5da69e962, 0x93eecc4d469073d9, 0xb92c99b1fafc114a, 0x77090a2f90aabbb4, 0x0ca69c28b2a9c210, 0xc9e0c08ca65ca101, 0x4b0ddca7d09d56e4, 0x988d03773833ba36,
        0x06534e1459da6108, 0x3a57989c19ed8c58, 0x0952f536491e1d1c, 0x0af5d23ceb73a318, 0x0d30812e2779a8e7, 0xd7e2abc886c95929, 0xa51fc8f9edd43d91, 0x690b616bb03f439c,
        0x516dc3fb9e6f1b37, 0xa489d5ff78045766, 0x52cae4f13c02a533, 0x4cc88fb51c975d1b, 0x459a7a8355894007, 0x9d796a69c384653a, 0x313457a6674e45b7, 0x4a9bc1a1454d3c13,
        0x6268ae51ce9c8a73, 0xfe87d93e98c885be, 0xff11c4380d18ef49, 0x8deca70966058bf1, 0xdeb05efecfd74435, 0xd027f8da4ac352d6, 0xf186621c880cf9aa, 0x43c934970c53210f,
        0xbee9caa336f61ab5, 0x56a890e9526510c8, 0xe8415a4a64930a7d, 0xe32295701a30c392, 0x3e35ec84778a39a3, 0x4f6fa8bfbefae31f, 0x5dcb5fd32cc6d927, 0x9f485065f439b1c9,
        0x1095cd60a581eecb, 0x978cb85528f7c622, 0x7baf9607220379a4, 0xd216c2d67d7e8625, 0xe4e7c662d63ac86d, 0xb62d2293ea386d5e, 0x8a29f41baa0f800e, 0x5ffa65df1b7b0dd4,
        0x61cf895b6cf13477, 0xa6b8eff34fb98395, 0x814a3b21d4ac49e1, 0xaddb20c9311a4a7a, 0x74ae2d2532c705b0, 0x30a24aa0f29e2f40, 0x91dff641712da72a, 0x9049eb47e4fdcddd,
        0x493ce6abe7208217, 0x36f104b4ab444e48, 0xf22145162a6147ae, 0x5c5d42d5b916b3d0, 0xf7d52c08d1d698a2, 0x7a398b01b7d31353, 0x6cff08754b889c90, 0x14f7b978cbe65b30,
        0xc4d041a2812509e6, 0xe085b27ab85d7d96, 0xc0b235baef42bc1d, 0x868f683318a6421e, 0xea706046532ede8e, 0x4ef9b5b92b2a89e8, 0xdc8164f2f86a90c6, 0x2455f3d839787470,
        0x5499aae565d8c43b, 0x59a92bcb42a16cdc, 0xa9b954d15f7dff81, 0xae7c07c39377f47e, 0x01961d0695d06af7, 0xdb4437e034609b39, 0x3bc1859a8c3de6af, 0xaa1e73dbfd104185,
        0x7dfcd8137bd918ac, 0x80dc2627417c2316, 0xd9750dec03dd4fca, 0xc5465ca414f56311, 0x203787c0571fc18b, 0xd5d391c4b1748dda, 0xc2830fb6d8ff68ee, 0xbcd8f0af014bce46,
        0xa0eba1e71663e29d, 0xfb73b020637f5ab2, 0x7c6ac515ee09725b, 0x0000000000000000, 0xc876dd8a338ccbf6, 0x9cef776f56540fcd, 0x47ab408f623494f4, 0xcbd1fa8091e175f2,
        0x9abc397b0f8e6ec5, 0xb58a05994855d35a, 0x4d5e92b3894737ec, 0x961aa553bd27acd5, 0xc31512b04d2f0219, 0xe6d6fc6ee1871c9e, 0xe2b488768fe0a965, 0xb3d94b8d118fb252,
        0x440c6785c0592af0, 0x25c3eedeaca81e87, 0x583f36cdd771062b, 0x2d0706ee7066696c, 0x425f299199834bf8, 0xfd20fe343aa53bba, 0xf643310e4406f255, 0xdad22ae6a1b0f1ce,
        0x1da54c4e82f8462c, 0x355623be0929f04c, 0x769f1729057ad143, 0xbd4eeda9949ba4b1, 0xd8e310ea960d253d, 0x736b7e37fecd0e4f, 0x65adfd430296818c, 0xb8ba84b76f2c7bbd,
        0x9b2a247d9a5e0432, 0xc77766a82348b7e2, 0x08c4e830dcce77eb, 0x0e97a624851416e3, 0x898ed31108623e0a, 0xe571db6443eaa29a, 0x573e8defc7b57a3f, 0x21a19ac6c2cfab7c,
        0x70cc593d5ca0b04b, 0x2664c9d40ec5a083, 0x296572f61e01dc97, 0x85284f39bacbfc1a, 0x715a443bc970dabc, 0xef840958a8990182, 0xcd82b494c83b14fa, 0x48aafbad72f0e8e0,
        0xe9d7474cf143608a, 0x2390a0caf5727f8f, 0xb7bb3f957fe807a9, 0x82ed1c2b76c1f7e5, 0xbb1da3bdcd41c5b9, 0x72fd63316b1d64b8, 0x7808b10d806ec7a0, 0x837b012de3119d12,
        0x689d7c6d25ef296b, 0x02313a0c37bdd4f3, 0x1103d0663051843c, 0xab886edd68c02b72, 0x6b3a5b678782976f, 0xe113af7c2d8d1761, 0x6aac46611252fd98, 0x50fbdefd0bbf71c0,
        0x2ea021e4d20bd768, 0x5a0e0cc1e0ccd2d8, 0x34c03eb89cf99abb, 0xb41c189fdd85b9ad, 0x9ede4d6361e9db3e, 0xafea1ac506a79e89, 0x463d5d89f7e4fe03, 0x18512550794f9920,
        0x41f80e9b3beef5fc, 0xa82f49d7caad9576, 0x0f01bb2210c47c14, 0xec232e520af4bf86, 0x1bf6025adb222724, 0xa2da9beb21de366e, 0xedb533549f24d571, 0x643be0459746eb7b,
        0xbf7fd7a5a3267042, 0x046274186e67b5fb, 0x8e4b8003c46835f5, 0x1332ea6a07ec50cf, 0xd380dfd0e8aeecd2, 0x6f582f7fe9e52294, 0xf9428a2c54c28e41, 0x3fa3f182e25a5354,
        0x535cf9f7a9d2cfc4, 0x660ada49a0fb3f88, 0x33056daa50f39144, 0x8fdd9d0551b85f02, 0x19c73856ec9ff3d7, 0xb1e87181263266a1, 0x1561a47e5e3631c7, 0xd4458cc224a4e72d,
        0xe740e16874577669, 0xc12428bc7a92d6ea, 0x3866a2902e5058ab, 0x1a601f5c4ef24dd3, 0x6059945df9215e80, 0x05f4691efbb7df0c, 0x5b9811c7751cb82f, 0x2b5448fa29bc0864,
        0xba8bbebb5891af4e, 0xf4720b0273bb26a6, 0xdd1779f46dbafa31, 0x6ece32797c354863, 0x7fcde21f4c64cc5f, 0x2206bdcc60a21578, 0x75383023a7176f47, 0xf3b75810bfb12d59,
    },
    {
        0x03d0663051843c11, 0xbfe91d3fdfeaf98b, 0xf80e9b3beef5fc41, 0xe5ad26f6af3045fa, 0x5a443bc970dabc71, 0x7b012de3119d1283, 0x82b494c83b14facd, 0x750dec03dd4fcad9,
        0x090a2f90aabbb477, 0xb6e332af75514dfc, 0xadfd430296818c65, 0xfd63316b1d64b872, 0x3d5d89f7e4fe0346, 0xd7474cf143608ae9, 0x7e6c87b3e20c56b0, 0x601f5c4ef24dd31a,
        0x40e16874577669e7, 0x4437e034609b39db, 0xe7c662d63ac86de4, 0xaf9607220379a47b, 0xea1ac506a79e89af, 0xd8f0af014bce46bc, 0x7fd7a5a3267042bf, 0x9f1729057ad14376,
        0x1c189fdd85b9adb4, 0x87d93e98c885befe, 0x57989c19ed8c583a, 0xa4f76c923c3a3812, 0x2a247d9a5e04329b, 0xc03eb89cf99abb34, 0xf6025adb2227241b, 0xa890e9526510c856,
        0x06bdcc60a2157822, 0xc73856ec9ff3d719, 0xcae4f13c02a53352, 0xd6fc6ee1871c9ee6, 0xf0bf96bb80325c39, 0x13af7c2d8d1761e1, 0x3be0459746eb7b64, 0x99aae565d8c43b54,
        0x95cd60a581eecb10, 0x68ae51ce9c8a7362, 0xcde21f4c64cc5f7f, 0xdc2627417c231680, 0x428a2c54c28e41f9, 0x76dd8a338ccbf6c8, 0xb8eff34fb98395a6, 0xa69c28b2a9c2100c,
        0x08b10d806ec7a078, 0xc55312cc0a0bff07, 0x886edd68c02b72ab, 0xdd9d0551b85f028f, 0x1e73dbfd104185aa, 0x911be8e5b6039b2c, 0x30812e2779a8e70d, 0x3a5b678782976f6b,
        0x20fe343aa53bbafd, 0xb954d15f7dff81a9, 0x9a7a835589400745, 0x1fc8f9edd43d91a5, 0x0e0cc1e0ccd2d85a, 0xbb3f957fe807a9b7, 0xc3eedeaca81e8725, 0x66a2902e5058ab38,
        0xff08754b889c906c, 0xfeb3575b4ce08463, 0x107f1a1ddc935df0, 0x25939e6a56aafece, 0xa92bcb42a16cdc59, 0x32ea6a07ec50cf13, 0x947642b54592df1f, 0x1779f46dbafa31dd,
        0x5623be0929f04c35, 0xf2d4d29b15ca7427, 0x59945df9215e8060, 0x9370acc523fbb332, 0xb05efecfd74435de, 0x71db6443eaa29ae5, 0xe2abc886c95929d7, 0x458cc224a4e72dd4,
        0xce32797c3548636e, 0x1aa553bd27acd596, 0x4a3b21d4ac49e181, 0x284f39bacbfc1a85, 0xd94b8d118fb252b3, 0xb235baef42bc1dc0, 0x2643f85a072ec2df, 0x8bbebb5891af4eba,
        0x89d5ff78045766a4, 0xeecc4d469073d993, 0x0b616bb03f439c69, 0xe41604e66b4c51f5, 0x16c2d67d7e8625d2, 0x6c78d98eab67235e, 0x9d7c6d25ef296b68, 0x64c9d40ec5a08326,
        0x2ef2f5da69e962a7, 0xfa65df1b7b0dd45f, 0x12145e3d496b75ee, 0xfcd8137bd918ac7d, 0x52f536491e1d1c09, 0xe67d40c6feb479eb, 0x2145162a6147aef2, 0x29f41baa0f800e8a,
        0x0000000000000000, 0x840958a8990182ef, 0xc88fb51c975d1b4c, 0xc68374fc5b8fc316, 0x5d42d5b916b3d05c, 0x7dbce183b3886aa1, 0x512550794f992018, 0xe17baeb698dd15c6,
        0x43310e4406f255f6, 0x6dc3fb9e6f1b3751, 0x86621c880cf9aaf1, 0xbc397b0f8e6ec59a, 0x415a4a64930a7de8, 0x04d6884037ed503c, 0xe9caa336f61ab5be, 0x0ada49a0fb3f8866,
        0x55f3d83978747024, 0x3ce6abe720821749, 0xf5d23ceb73a3180a, 0xa24aa0f29e2f4030, 0x582f7fe9e522946f, 0x7aba0ff3d5e1068c, 0x313a0c37bdd4f302, 0x3787c0571fc18b20,
        0x5cf9f7a9d2cfc453, 0xbe523f2f1b96ed84, 0x85b27ab85d7d96e0, 0x0706ee7066696c2d, 0x961d0695d06af701, 0x1b1e71ade3d0c199, 0xc255fcbc6c62932a, 0x398b01b7d313537a,
        0xcc593d5ca0b04b70, 0x5f299199834bf842, 0x80dfd0e8aeecd2d3, 0x9eac0b15bead5779, 0xef776f56540fcd9c, 0x2f49d7caad9576a8, 0x2c99b1fafc114ab9, 0x8d03773833ba3698,
        0x720b0273bb26a6f4, 0x18ce179db254fd88, 0x8f683318a6421e86, 0x4f568b845fd8a5b2, 0x8ed31108623e0a89, 0xd22ae6a1b0f1ceda, 0x74b6ce131933ded6, 0x97a624851416e30e,
        0x6e139dae3e9f0b40, 0xa7270aa26dbe0403, 0x5448fa29bc08642b, 0xe310ea960d253dd8, 0x706046532ede8eea, 0x485065f439b1c99f, 0x6b7e37fecd0e4f73, 0xfbdefd0bbf71c050,
        0xd391c4b1748ddad5, 0xa021e4d20bd7682e, 0xab408f623494f447, 0x5bff19d9b4a6a87e, 0xb1e5dcdf133821d1, 0x026b442095f8281e, 0xdff641712da72a91, 0x11c4380d18ef49ff,
        0xae2d2532c705b074, 0xc1859a8c3de6af3b, 0x4b8003c46835f58e, 0x92cb8ed5e787a73d, 0xcb5fd32cc6d9275d, 0x8cb85528f7c62297, 0x9bc1a1454d3c134a, 0x056daa50f3914433,
        0xf4691efbb7df0c05, 0xd1fa8091e175f2cb, 0x7c07c39377f47eae, 0x14a9925deb7e0dcc, 0xcf895b6cf1347761, 0x0fb7e3f008aecc55, 0x8a05994855d35ab5, 0xf104b4ab444e4836,
        0x691573de58f6676d, 0x4eeda9949ba4b1bd, 0x2428bc7a92d6eac1, 0xb75810bfb12d59f3, 0x63cf3a7ea3c9ef0b, 0x6274186e67b5fb04, 0x1512b04d2f0219c3, 0xe87181263266a1b1,
        0x1975358d7628e987, 0x534e1459da610806, 0x47e78604311f05ca, 0xd4972ac112e4b6f8, 0x33514817282cdb1c, 0x90a0caf5727f8f23, 0x3e8defc7b57a3f57, 0x3f36cdd771062b58,
        0x796a69c384653a9d, 0x465ca414f56311c5, 0x5e92b3894737ec4d, 0x9811c7751cb82f5b, 0xd041a2812509e6c4, 0x49eb47e4fdcddd90, 0x78d14bd340192e92, 0xf9b5b92b2a89e84e,
        0x61a47e5e3631c715, 0x509e72698be53417, 0xb533549f24d571ed, 0x27f8da4ac352d6d0, 0x6572f61e01dc9729, 0xde4d6361e9db3e9e, 0x3457a6674e45b731, 0xa54c4e82f8462c1d,
        0xbd82591f4a12d195, 0x830fb6d8ff68eec2, 0x383023a7176f4775, 0x7766a82348b7e2c7, 0x0c6785c0592af044, 0xba84b76f2c7bbdb8, 0xe0c08ca65ca101c9, 0xeba1e71663e29da0,
        0xd52c08d1d698a2f7, 0xc4e830dcce77eb08, 0xda9beb21de366ea2, 0xa3f182e25a53543f, 0xac46611252fd986a, 0xb38e98ff86c009cf, 0xf36ff08bd1b66028, 0xdb20c9311a4a7aad,
        0xa19ac6c2cfab7c21, 0x6ac515ee09725b7c, 0x4c86edb40e5c99a3, 0x363ce247dbbd9f2f, 0x8164f2f86a90c6dc, 0x35ec84778a39a33e, 0xb488768fe0a965e2, 0x73b020637f5ab2fb,
        0x232e520af4bf86ec, 0x6fa8bfbefae31f4f, 0xeca70966058bf18d, 0x1da3bdcd41c5b9bb, 0x9cc74f352b557f67, 0x4d3dcfa4ca208dac, 0x2b9f5f8a9a782694, 0xaafbad72f0e8e048,
        0xc934970c53210f43, 0xed1c2b76c1f7e582, 0x01bb2210c47c140f, 0x0ddca7d09d56e44b, 0x2d2293ea386d5eb6, 0xf7b978cbe65b3014, 0x6719b23e9424bf37, 0x2295701a30c392e3,
    },
    {
        0x9f5f8a9a7826942b, 0x34970c53210f43c9, 0x9d0551b85f028fdd, 0xb494c83b14facd82, 0x6edd68c02b72ab88, 0xff19d9b4a6a87e5b, 0xdb6443eaa29ae571, 0x1be8e5b6039b2c91,
        0x5fd32cc6d9275dcb, 0x90e9526510c856a8, 0xb27ab85d7d96e085, 0xa47e5e3631c71561, 0xf3d8397874702455, 0xfbad72f0e8e048aa, 0x37e034609b39db44, 0xfa8091e175f2cbd1,
        0xcaa336f61ab5bee9, 0xeff34fb98395a6b8, 0x63316b1d64b872fd, 0xba0ff3d5e1068c7a, 0xcd60a581eecb1095, 0x35baef42bc1dc0b2, 0x23be0929f04c3556, 0x4b8d118fb252b3d9,
        0xd8137bd918ac7dfc, 0x0a2f90aabbb47709, 0xc2d67d7e8625d216, 0x7181263266a1b1e8, 0x3023a7176f477538, 0x7642b54592df1f94, 0xf2f5da69e962a72e, 0xa70966058bf18dec,
        0xc662d63ac86de4e7, 0x939e6a56aafece25, 0x86edb40e5c99a34c, 0xf8da4ac352d6d027, 0x145e3d496b75ee12, 0xce179db254fd8818, 0xd23ceb73a3180af5, 0x270aa26dbe0403a7,
        0x5d89f7e4fe03463d, 0x2ae6a1b0f1cedad2, 0x1729057ad143769f, 0xb10d806ec7a07808, 0x4f39bacbfc1a8528, 0xeda9949ba4b1bd4e, 0x5312cc0a0bff07c5, 0xc4380d18ef49ff11,
        0x95701a30c392e322, 0xa0caf5727f8f2390, 0x55fcbc6c62932ac2, 0xcf3a7ea3c9ef0b63, 0x621c880cf9aaf186, 0xfd430296818c65ad, 0xbf96bb80325c39f0, 0x6c87b3e20c56b07e,
        0x299199834bf8425f, 0x74186e67b5fb0462, 0x4c4e82f8462c1da5, 0x64f2f86a90c6dc81, 0x6b442095f8281e02, 0x1d0695d06af70196, 0xd5ff78045766a489, 0x3856ec9ff3d719c7,
        0xac0b15bead57799e, 0xc3fb9e6f1b37516d, 0x8e98ff86c009cfb3, 0x49d7caad9576a82f, 0x859a8c3de6af3bc1, 0x3dcfa4ca208dac4d, 0x91c4b1748ddad5d3, 0x8a2c54c28e41f942,
        0x2bcb42a16cdc59a9, 0x9e72698be5341750, 0x1e71ade3d0c1991b, 0xe6abe7208217493c, 0x3a0c37bdd4f30231, 0x945df9215e806059, 0xcc4d469073d993ee, 0x0e9b3beef5fc41f8,
        0x8b01b7d313537a39, 0xf182e25a53543fa3, 0x5810bfb12d59f3b7, 0x8003c46835f58e4b, 0xbce183b3886aa17d, 0x1604e66b4c51f5e4, 0x2c08d1d698a2f7d5, 0xc08ca65ca101c9e0,
        0x7a8355894007459a, 0xe21f4c64cc5f7fcd, 0x88768fe0a965e2b4, 0x82591f4a12d195bd, 0x4aa0f29e2f4030a2, 0xdca7d09d56e44b0d, 0x6daa50f391443305, 0x92b3894737ec4d5e,
        0xa8bfbefae31f4f6f, 0xea6a07ec50cf1332, 0x2293ea386d5eb62d, 0x41a2812509e6c4d0, 0x8374fc5b8fc316c6, 0x683318a6421e868f, 0xb3575b4ce08463fe, 0xe5dcdf133821d1b1,
        0xd6884037ed503c04, 0x05994855d35ab58a, 0x5b678782976f6b3a, 0x397b0f8e6ec59abc, 0xabc886c95929d7e2, 0xe4f13c02a53352ca, 0xb5b92b2a89e84ef9, 0xaf7c2d8d1761e113,
        0x75358d7628e98719, 0x72f61e01dc972965, 0x78d98eab67235e6c, 0xc8f9edd43d91a51f, 0x0fb6d8ff68eec283, 0x70acc523fbb33293, 0x36cdd771062b583f, 0xbdcc60a215782206,
        0xa624851416e30e97, 0x9607220379a47baf, 0x1c2b76c1f7e582ed, 0x6046532ede8eea70, 0xbebb5891af4eba8b, 0x48fa29bc08642b54, 0x19b23e9424bf3767, 0x2627417c231680dc,
        0x65df1b7b0dd45ffa, 0xf536491e1d1c0952, 0x54d15f7dff81a9b9, 0x2550794f99201851, 0xdefd0bbf71c050fb, 0x87c0571fc18b2037, 0x10ea960d253dd8e3, 0xe0459746eb7b643b,
        0x12b04d2f0219c315, 0xaae565d8c43b5499, 0xe91d3fdfeaf98bbf, 0xf76c923c3a3812a4, 0x1f5c4ef24dd31a60, 0x812e2779a8e70d30, 0xf41baa0f800e8a29, 0xfc6ee1871c9ee6d6,
        0x8fb51c975d1b4cc8, 0x4e1459da61080653, 0x310e4406f255f643, 0x0cc1e0ccd2d85a0e, 0x0958a8990182ef84, 0xa9925deb7e0dcc14, 0x6a69c384653a9d79, 0x04b4ab444e4836f1,
        0x0dec03dd4fcad975, 0xeb47e4fdcddd9049, 0x7e37fecd0e4f736b, 0x73dbfd104185aa1e, 0xc515ee09725b7c6a, 0xae51ce9c8a736268, 0xa3bdcd41c5b9bb1d, 0x84b76f2c7bbdb8ba,
        0x443bc970dabc715a, 0xa1e71663e29da0eb, 0x7f1a1ddc935df010, 0x474cf143608ae9d7, 0x33549f24d571edb5, 0xc9d40ec5a0832664, 0x46611252fd986aac, 0x5efecfd74435deb0,
        0x0000000000000000, 0x514817282cdb1c33, 0x408f623494f447ab, 0x57a6674e45b73134, 0x11c7751cb82f5b98, 0x989c19ed8c583a57, 0x7baeb698dd15c6e1, 0x06ee7066696c2d07,
        0xda49a0fb3f88660a, 0x07c39377f47eae7c, 0x2d2532c705b074ae, 0x42d5b916b3d05c5d, 0xec84778a39a33e35, 0x776f56540fcd9cef, 0xa553bd27acd5961a, 0xb978cbe65b3014f7,
        0x895b6cf1347761cf, 0xb85528f7c622978c, 0x66a82348b7e2c777, 0xe830dcce77eb08c4, 0x189fdd85b9adb41c, 0x99b1fafc114ab92c, 0x0b0273bb26a6f472, 0xeedeaca81e8725c3,
        0x6785c0592af0440c, 0x247d9a5e04329b2a, 0x21e4d20bd7682ea0, 0xbb2210c47c140f01, 0x523f2f1b96ed84be, 0xd4d29b15ca7427f2, 0x45162a6147aef221, 0xf641712da72a91df,
        0xb020637f5ab2fb73, 0xdd8a338ccbf6c876, 0x5ca414f56311c546, 0x3f957fe807a9b7bb, 0x8cc224a4e72dd445, 0x012de3119d12837b, 0xd0663051843c1103, 0x5a4a64930a7de841,
        0x28bc7a92d6eac124, 0x08754b889c906cff, 0xd7a5a3267042bf7f, 0x3ce247dbbd9f2f36, 0x6ff08bd1b66028f3, 0xd14bd340192e9278, 0x139dae3e9f0b406e, 0xe78604311f05ca47,
        0xd93e98c885befe87, 0x616bb03f439c690b, 0x03773833ba36988d, 0xcb8ed5e787a73d92, 0xb7e3f008aecc550f, 0x9c28b2a9c2100ca6, 0x3eb89cf99abb34c0, 0x3b21d4ac49e1814a,
        0xdfd0e8aeecd2d380, 0x7c6d25ef296b689d, 0xc1a1454d3c134a9b, 0xf9f7a9d2cfc4535c, 0xc74f352b557f679c, 0x7d40c6feb479ebe6, 0x1573de58f6676d69, 0x1ac506a79e89afea,
        0x568b845fd8a5b24f, 0x32797c3548636ece, 0x691efbb7df0c05f4, 0x972ac112e4b6f8d4, 0x79f46dbafa31dd17, 0x2e520af4bf86ec23, 0xd31108623e0a898e, 0x8defc7b57a3f573e,
        0x025adb2227241bf6, 0xa2902e5058ab3866, 0xfe343aa53bbafd20, 0xad26f6af3045fae5, 0x43f85a072ec2df26, 0x2f7fe9e522946f58, 0x9beb21de366ea2da, 0x20c9311a4a7aaddb,
        0x5065f439b1c99f48, 0x593d5ca0b04b70cc, 0x9ac6c2cfab7c21a1, 0xb6ce131933ded674, 0xf0af014bce46bcd8, 0x4d6361e9db3e9ede, 0xe16874577669e740, 0xe332af75514dfcb6,
    },
    {
        0xbfbefae31f4f6fa8, 0x85c0592af0440c67, 0xbaef42bc1dc0b235, 0x5528f7c622978cb8, 0xe6a1b0f1cedad22a, 0x3ceb73a3180af5d2, 0x7fe9e522946f582f, 0xa7d09d56e44b0ddc,
        0x754b889c906cff08, 0xe247dbbd9f2f363c, 0x81263266a1b1e871, 0xdcdf133821d1b1e5, 0xf46dbafa31dd1779, 0x3d5ca0b04b70cc59, 0x56ec9ff3d719c738, 0xdeaca81e8725c3ee,
        0x549f24d571edb533, 0x2de3119d12837b01, 0xea960d253dd8e310, 0xc886c95929d7e2ab, 0x2f90aabbb477090a, 0x26f6af3045fae5ad, 0x6ee1871c9ee6d6fc, 0x3e98c885befe87d9,
        0x24851416e30e97a6, 0xda4ac352d6d027f8, 0xe3f008aecc550fb7, 0x994855d35ab58a05, 0x5df9215e80605994, 0x58a8990182ef8409, 0xb1fafc114ab92c99, 0x442095f8281e026b,
        0xf5da69e962a72ef2, 0xc0571fc18b203787, 0x37fecd0e4f736b7e, 0x902e5058ab3866a2, 0xeb21de366ea2da9b, 0x8f623494f447ab40, 0xd98eab67235e6c78, 0xa414f56311c5465c,
        0x5c4ef24dd31a601f, 0x08d1d698a2f7d52c, 0xdbfd104185aa1e73, 0xcb42a16cdc59a92b, 0x10bfb12d59f3b758, 0xa82348b7e2c77766, 0xbdcd41c5b9bb1da3, 0x7ab85d7d96e085b2,
        0xedb40e5c99a34c86, 0xff78045766a489d5, 0xf34fb98395a6b8ef, 0x4f352b557f679cc7, 0x4a64930a7de8415a, 0xe8e5b6039b2c911b, 0xb4ab444e4836f104, 0x4817282cdb1c3351,
        0xaeb698dd15c6e17b, 0x3f2f1b96ed84be52, 0x21d4ac49e1814a3b, 0x884037ed503c04d6, 0xbe0929f04c355623, 0xe565d8c43b5499aa, 0x1108623e0a898ed3, 0x2532c705b074ae2d,
        0x0551b85f028fdd9d, 0x03c46835f58e4b80, 0xf13c02a53352cae4, 0xee7066696c2d0706, 0xc6c2cfab7c21a19a, 0xb04d2f0219c31512, 0x0273bb26a6f4720b, 0x8604311f05ca47e7,
        0xaf014bce46bcd8f0, 0x3318a6421e868f68, 0x96bb80325c39f0bf, 0x40c6feb479ebe67d, 0x12cc0a0bff07c553, 0x162a6147aef22145, 0x71ade3d0c1991b1e, 0xce131933ded674b6,
        0xc9311a4a7aaddb20, 0x32af75514dfcb6e3, 0x62d63ac86de4e7c6, 0xb23e9424bf376719, 0x8355894007459a7a, 0x137bd918ac7dfcd8, 0x42b54592df1f9476, 0xabe7208217493ce6,
        0x9b3beef5fc41f80e, 0x2e2779a8e70d3081, 0x4d469073d993eecc, 0x768fe0a965e2b488, 0xd0e8aeecd2d380df, 0xa2812509e6c4d041, 0x0ff3d5e1068c7aba, 0x04e66b4c51f5e416,
        0x2c54c28e41f9428a, 0x01b7d313537a398b, 0xcc60a215782206bd, 0xc506a79e89afea1a, 0x4cf143608ae9d747, 0x8a338ccbf6c876dd, 0x29057ad143769f17, 0xcfa4ca208dac4d3d,
        0xa6674e45b7313457, 0x50794f9920185125, 0xb89cf99abb34c03e, 0x343aa53bbafd20fe, 0x89f7e4fe03463d5d, 0xa5a3267042bf7fd7, 0xefc7b57a3f573e8d, 0x9fdd85b9adb41c18,
        0xec03dd4fcad9750d, 0x970c53210f43c934, 0xc7751cb82f5b9811, 0xc1e0ccd2d85a0e0c, 0xad72f0e8e048aafb, 0x0966058bf18deca7, 0x47e4fdcddd9049eb, 0x19d9b4a6a87e5bff,
        0x1a1ddc935df0107f, 0x591f4a12d195bd82, 0x1efbb7df0c05f469, 0x575b4ce08463feb3, 0x0e4406f255f64331, 0x2ac112e4b6f8d497, 0xa0f29e2f4030a24a, 0x179db254fd8818ce,
        0x663051843c1103d0, 0xe4d20bd7682ea021, 0xd15f7dff81a9b954, 0xd32cc6d9275dcb5f, 0x94c83b14facd82b4, 0xaa50f3914433056d, 0x358d7628e9871975, 0xbc7a92d6eac12428,
        0x39bacbfc1a85284f, 0x9199834bf8425f29, 0x73de58f6676d6915, 0xd5b916b3d05c5d42, 0x46532ede8eea7060, 0x186e67b5fb046274, 0xa1454d3c134a9bc1, 0x0b15bead57799eac,
        0x5adb2227241bf602, 0xdd68c02b72ab886e, 0x6443eaa29ae571db, 0xfd0bbf71c050fbde, 0x8b845fd8a5b24f56, 0xb92b2a89e84ef9b5, 0x678782976f6b3a5b, 0xf2f86a90c6dc8164,
        0xc39377f47eae7c07, 0x93ea386d5eb62d22, 0x430296818c65adfd, 0xc224a4e72dd4458c, 0x9e6a56aafece2593, 0x6f56540fcd9cef77, 0x84778a39a33e35ec, 0xf85a072ec2df2643,
        0x3bc970dabc715a44, 0x0d806ec7a07808b1, 0x773833ba36988d03, 0x27417c231680dc26, 0x60a581eecb1095cd, 0xb76f2c7bbdb8ba84, 0xd8397874702455f3, 0xfecfd74435deb05e,
        0xcaf5727f8f2390a0, 0xa9949ba4b1bd4eed, 0xe034609b39db4437, 0x2b76c1f7e582ed1c, 0xf7a9d2cfc4535cf9, 0x20637f5ab2fb73b0, 0x9c19ed8c583a5798, 0xd67d7e8625d216c2,
        0x1459da610806534e, 0x6d25ef296b689d7c, 0x925deb7e0dcc14a9, 0x65f439b1c99f4850, 0x957fe807a9b7bb3f, 0x41712da72a91dff6, 0x36491e1d1c0952f5, 0x5e3d496b75ee1214,
        0x1d3fdfeaf98bbfe9, 0x701a30c392e32295, 0x6361e9db3e9ede4d, 0xd7caad9576a82f49, 0xe71663e29da0eba1, 0x98ff86c009cfb38e, 0x6bb03f439c690b61, 0xc4b1748ddad5d391,
        0x6c923c3a3812a4f7, 0x1f4c64cc5f7fcde2, 0xe183b3886aa17dbc, 0xb6d8ff68eec2830f, 0x51ce9c8a736268ae, 0x07220379a47baf96, 0x82e25a53543fa3f1, 0xbb5891af4eba8bbe,
        0x4bd340192e9278d1, 0x6874577669e740e1, 0xfb9e6f1b37516dc3, 0xacc523fbb3329370, 0x69c384653a9d796a, 0x5b6cf1347761cf89, 0x0000000000000000, 0x49a0fb3f88660ada,
        0xa336f61ab5bee9ca, 0x15ee09725b7c6ac5, 0x8d118fb252b3d94b, 0x7d9a5e04329b2a24, 0x1baa0f800e8a29f4, 0xfa29bc08642b5448, 0x459746eb7b643be0, 0xdf1b7b0dd45ffa65,
        0x30dcce77eb08c4e8, 0x8091e175f2cbd1fa, 0x0c37bdd4f302313a, 0xf9edd43d91a51fc8, 0x3a7ea3c9ef0b63cf, 0x74fc5b8fc316c683, 0x8ca65ca101c9e0c0, 0x72698be53417509e,
        0x23a7176f47753830, 0x797c3548636ece32, 0xb51c975d1b4cc88f, 0x2210c47c140f01bb, 0xd29b15ca7427f2d4, 0x8ed5e787a73d92cb, 0x7e5e3631c71561a4, 0x1c880cf9aaf18662,
        0xf08bd1b66028f36f, 0xf61e01dc97296572, 0x7b0f8e6ec59abc39, 0xb3894737ec4d5e92, 0x316b1d64b872fd63, 0x9a8c3de6af3bc185, 0x0aa26dbe0403a727, 0x5f8a9a7826942b9f,
        0x520af4bf86ec232e, 0x380d18ef49ff11c4, 0x0695d06af701961d, 0x87b3e20c56b07e6c, 0x53bd27acd5961aa5, 0x7c2d8d1761e113af, 0x28b2a9c2100ca69c, 0x6a07ec50cf1332ea,
        0xe9526510c856a890, 0xcdd771062b583f36, 0xfcbc6c62932ac255, 0x9dae3e9f0b406e13, 0xd40ec5a0832664c9, 0x78cbe65b3014f7b9, 0x4e82f8462c1da54c, 0x611252fd986aac46,
    },
    {
        0x352b557f679cc74f, 0x3e9424bf376719b2, 0x5deb7e0dcc14a992, 0xb3e20c56b07e6c87, 0x83b3886aa17dbce1, 0x3d496b75ee12145e, 0xae3e9f0b406e139d, 0x8a9a7826942b9f5f,
        0x845fd8a5b24f568b, 0x5a072ec2df2643f8, 0xf3d5e1068c7aba0f, 0x7ea3c9ef0b63cf3a, 0x923c3a3812a4f76c, 0x3fdfeaf98bbfe91d, 0xd340192e9278d14b, 0x04311f05ca47e786,
        0xcc0a0bff07c55312, 0xff86c009cfb38e98, 0xade3d0c1991b1e71, 0xfc5b8fc316c68374, 0xbb80325c39f0bf96, 0xd5e787a73d92cb8e, 0xa4ca208dac4d3dcf, 0xf6af3045fae5ad26,
        0x5b4ce08463feb357, 0x8bd1b66028f36ff0, 0xb698dd15c6e17bae, 0x2f1b96ed84be523f, 0x4037ed503c04d688, 0x6a56aafece25939e, 0xb40e5c99a34c86ed, 0xc6feb479ebe67d40,
        0x9b15ca7427f2d4d2, 0xde58f6676d691573, 0xc523fbb3329370ac, 0xe5b6039b2c911be8, 0x8d7628e987197535, 0xf008aecc550fb7e3, 0xd9b4a6a87e5bff19, 0xc112e4b6f8d4972a,
        0xdf133821d1b1e5dc, 0xaf75514dfcb6e332, 0x2095f8281e026b44, 0xb54592df1f947642, 0x8eab67235e6c78d9, 0x698be53417509e72, 0xbc6c62932ac255fc, 0x1f4a12d195bd8259,
        0x15bead57799eac0b, 0x1ddc935df0107f1a, 0x131933ded674b6ce, 0xe66b4c51f5e41604, 0x9db254fd8818ce17, 0xa26dbe0403a7270a, 0x17282cdb1c335148, 0x47dbbd9f2f363ce2,
        0xda69e962a72ef2f5, 0x469073d993eecc4d, 0xfafc114ab92c99b1, 0x90aabbb477090a2f, 0xb2a9c2100ca69c28, 0xa65ca101c9e0c08c, 0xd09d56e44b0ddca7, 0x3833ba36988d0377,
        0x59da610806534e14, 0x19ed8c583a57989c, 0x491e1d1c0952f536, 0xeb73a3180af5d23c, 0x2779a8e70d30812e, 0x86c95929d7e2abc8, 0xedd43d91a51fc8f9, 0xb03f439c690b616b,
        0x9e6f1b37516dc3fb, 0x78045766a489d5ff, 0x3c02a53352cae4f1, 0x1c975d1b4cc88fb5, 0x55894007459a7a83, 0xc384653a9d796a69, 0x674e45b7313457a6, 0x454d3c134a9bc1a1,
        0xce9c8a736268ae51, 0x98c885befe87d93e, 0x0d18ef49ff11c438, 0x66058bf18deca709, 0xcfd74435deb05efe, 0x4ac352d6d027f8da, 0x880cf9aaf186621c, 0x0c53210f43c93497,
        0x36f61ab5bee9caa3, 0x526510c856a890e9, 0x64930a7de8415a4a, 0x1a30c392e3229570, 0x778a39a33e35ec84, 0xbefae31f4f6fa8bf, 0x2cc6d9275dcb5fd3, 0xf439b1c99f485065,
        0xa581eecb1095cd60, 0x28f7c622978cb855, 0x220379a47baf9607, 0x7d7e8625d216c2d6, 0xd63ac86de4e7c662, 0xea386d5eb62d2293, 0xaa0f800e8a29f41b, 0x1b7b0dd45ffa65df,
        0x6cf1347761cf895b, 0x4fb98395a6b8eff3, 0xd4ac49e1814a3b21, 0x311a4a7aaddb20c9, 0x32c705b074ae2d25, 0xf29e2f4030a24aa0, 0x712da72a91dff641, 0xe4fdcddd9049eb47,
        0xe7208217493ce6ab, 0xab444e4836f104b4, 0x2a6147aef2214516, 0xb916b3d05c5d42d5, 0xd1d698a2f7d52c08, 0xb7d313537a398b01, 0x4b889c906cff0875, 0xcbe65b3014f7b978,
        0x812509e6c4d041a2, 0xb85d7d96e085b27a, 0xef42bc1dc0b235ba, 0x18a6421e868f6833, 0x532ede8eea706046, 0x2b2a89e84ef9b5b9, 0xf86a90c6dc8164f2, 0x397874702455f3d8,
        0x65d8c43b5499aae5, 0x42a16cdc59a92bcb, 0x5f7dff81a9b954d1, 0x9377f47eae7c07c3, 0x95d06af701961d06, 0x34609b39db4437e0, 0x8c3de6af3bc1859a, 0xfd104185aa1e73db,
        0x7bd918ac7dfcd813, 0x417c231680dc2627, 0x03dd4fcad9750dec, 0x14f56311c5465ca4, 0x571fc18b203787c0, 0xb1748ddad5d391c4, 0xd8ff68eec2830fb6, 0x014bce46bcd8f0af,
        0x1663e29da0eba1e7, 0x637f5ab2fb73b020, 0xee09725b7c6ac515, 0x0000000000000000, 0x338ccbf6c876dd8a, 0x56540fcd9cef776f, 0x623494f447ab408f, 0x91e175f2cbd1fa80,
        0x0f8e6ec59abc397b, 0x4855d35ab58a0599, 0x894737ec4d5e92b3, 0xbd27acd5961aa553, 0x4d2f0219c31512b0, 0xe1871c9ee6d6fc6e, 0x8fe0a965e2b48876, 0x118fb252b3d94b8d,
        0xc0592af0440c6785, 0xaca81e8725c3eede, 0xd771062b583f36cd, 0x7066696c2d0706ee, 0x99834bf8425f2991, 0x3aa53bbafd20fe34, 0x4406f255f643310e, 0xa1b0f1cedad22ae6,
        0x82f8462c1da54c4e, 0x0929f04c355623be, 0x057ad143769f1729, 0x949ba4b1bd4eeda9, 0x960d253dd8e310ea, 0xfecd0e4f736b7e37, 0x0296818c65adfd43, 0x6f2c7bbdb8ba84b7,
        0x9a5e04329b2a247d, 0x2348b7e2c77766a8, 0xdcce77eb08c4e830, 0x851416e30e97a624, 0x08623e0a898ed311, 0x43eaa29ae571db64, 0xc7b57a3f573e8def, 0xc2cfab7c21a19ac6,
        0x5ca0b04b70cc593d, 0x0ec5a0832664c9d4, 0x1e01dc97296572f6, 0xbacbfc1a85284f39, 0xc970dabc715a443b, 0xa8990182ef840958, 0xc83b14facd82b494, 0x72f0e8e048aafbad,
        0xf143608ae9d7474c, 0xf5727f8f2390a0ca, 0x7fe807a9b7bb3f95, 0x76c1f7e582ed1c2b, 0xcd41c5b9bb1da3bd, 0x6b1d64b872fd6331, 0x806ec7a07808b10d, 0xe3119d12837b012d,
        0x25ef296b689d7c6d, 0x37bdd4f302313a0c, 0x3051843c1103d066, 0x68c02b72ab886edd, 0x8782976f6b3a5b67, 0x2d8d1761e113af7c, 0x1252fd986aac4661, 0x0bbf71c050fbdefd,
        0xd20bd7682ea021e4, 0xe0ccd2d85a0e0cc1, 0x9cf99abb34c03eb8, 0xdd85b9adb41c189f, 0x61e9db3e9ede4d63, 0x06a79e89afea1ac5, 0xf7e4fe03463d5d89, 0x794f992018512550,
        0x3beef5fc41f80e9b, 0xcaad9576a82f49d7, 0x10c47c140f01bb22, 0x0af4bf86ec232e52, 0xdb2227241bf6025a, 0x21de366ea2da9beb, 0x9f24d571edb53354, 0x9746eb7b643be045,
        0xa3267042bf7fd7a5, 0x6e67b5fb04627418, 0xc46835f58e4b8003, 0x07ec50cf1332ea6a, 0xe8aeecd2d380dfd0, 0xe9e522946f582f7f, 0x54c28e41f9428a2c, 0xe25a53543fa3f182,
        0xa9d2cfc4535cf9f7, 0xa0fb3f88660ada49, 0x50f3914433056daa, 0x51b85f028fdd9d05, 0xec9ff3d719c73856, 0x263266a1b1e87181, 0x5e3631c71561a47e, 0x24a4e72dd4458cc2,
        0x74577669e740e168, 0x7a92d6eac12428bc, 0x2e5058ab3866a290, 0x4ef24dd31a601f5c, 0xf9215e806059945d, 0xfbb7df0c05f4691e, 0x751cb82f5b9811c7, 0x29bc08642b5448fa,
        0x5891af4eba8bbebb, 0x73bb26a6f4720b02, 0x6dbafa31dd1779f4, 0x7c3548636ece3279, 0x4c64cc5f7fcde21f, 0x60a215782206bdcc, 0xa7176f4775383023, 0xbfb12d59f3b75810,
    },
    {
        0x51843c1103d06630, 0xdfeaf98bbfe91d3f, 0xeef5fc41f80e9b3b, 0xaf3045fae5ad26f6, 0x70dabc715a443bc9, 0x119d12837b012de3, 0x3b14facd82b494c8, 0xdd4fcad9750dec03,
        0xaabbb477090a2f90, 0x75514dfcb6e332af, 0x96818c65adfd4302, 0x1d64b872fd63316b, 0xe4fe03463d5d89f7, 0x43608ae9d7474cf1, 0xe20c56b07e6c87b3, 0xf24dd31a601f5c4e,
        0x577669e740e16874, 0x609b39db4437e034, 0x3ac86de4e7c662d6, 0x0379a47baf960722, 0xa79e89afea1ac506, 0x4bce46bcd8f0af01, 0x267042bf7fd7a5a3, 0x7ad143769f172905,
        0x85b9adb41c189fdd, 0xc885befe87d93e98, 0xed8c583a57989c19, 0x3c3a3812a4f76c92, 0x5e04329b2a247d9a, 0xf99abb34c03eb89c, 0x2227241bf6025adb, 0x6510c856a890e952,
        0xa215782206bdcc60, 0x9ff3d719c73856ec, 0x02a53352cae4f13c, 0x871c9ee6d6fc6ee1, 0x80325c39f0bf96bb, 0x8d1761e113af7c2d, 0x46eb7b643be04597, 0xd8c43b5499aae565,
        0x81eecb1095cd60a5, 0x9c8a736268ae51ce, 0x64cc5f7fcde21f4c, 0x7c231680dc262741, 0xc28e41f9428a2c54, 0x8ccbf6c876dd8a33, 0xb98395a6b8eff34f, 0xa9c2100ca69c28b2,
        0x6ec7a07808b10d80, 0x0a0bff07c55312cc, 0xc02b72ab886edd68, 0xb85f028fdd9d0551, 0x104185aa1e73dbfd, 0xb6039b2c911be8e5, 0x79a8e70d30812e27, 0x82976f6b3a5b6787,
        0xa53bbafd20fe343a, 0x7dff81a9b954d15f, 0x894007459a7a8355, 0xd43d91a51fc8f9ed, 0xccd2d85a0e0cc1e0, 0xe807a9b7bb3f957f, 0xa81e8725c3eedeac, 0x5058ab3866a2902e,
        0x889c906cff08754b, 0x4ce08463feb3575b, 0xdc935df0107f1a1d, 0x56aafece25939e6a, 0xa16cdc59a92bcb42, 0xec50cf1332ea6a07, 0x4592df1f947642b5, 0xbafa31dd1779f46d,
        0x29f04c355623be09, 0x15ca7427f2d4d29b, 0x215e806059945df9, 0x23fbb3329370acc5, 0xd74435deb05efecf, 0xeaa29ae571db6443, 0xc95929d7e2abc886, 0xa4e72dd4458cc224,
        0x3548636ece32797c, 0x27acd5961aa553bd, 0xac49e1814a3b21d4, 0xcbfc1a85284f39ba, 0x8fb252b3d94b8d11, 0x42bc1dc0b235baef, 0x072ec2df2643f85a, 0x91af4eba8bbebb58,
        0x045766a489d5ff78, 0x9073d993eecc4d46, 0x3f439c690b616bb0, 0x6b4c51f5e41604e6, 0x7e8625d216c2d67d, 0xab67235e6c78d98e, 0xef296b689d7c6d25, 0xc5a0832664c9d40e,
        0x69e962a72ef2f5da, 0x7b0dd45ffa65df1b, 0x496b75ee12145e3d, 0xd918ac7dfcd8137b, 0x1e1d1c0952f53649, 0xfeb479ebe67d40c6, 0x6147aef22145162a, 0x0f800e8a29f41baa,
        0x0000000000000000, 0x990182ef840958a8, 0x975d1b4cc88fb51c, 0x5b8fc316c68374fc, 0x16b3d05c5d42d5b9, 0xb3886aa17dbce183, 0x4f99201851255079, 0x98dd15c6e17baeb6,
        0x06f255f643310e44, 0x6f1b37516dc3fb9e, 0x0cf9aaf186621c88, 0x8e6ec59abc397b0f, 0x930a7de8415a4a64, 0x37ed503c04d68840, 0xf61ab5bee9caa336, 0xfb3f88660ada49a0,
        0x7874702455f3d839, 0x208217493ce6abe7, 0x73a3180af5d23ceb, 0x9e2f4030a24aa0f2, 0xe522946f582f7fe9, 0xd5e1068c7aba0ff3, 0xbdd4f302313a0c37, 0x1fc18b203787c057,
        0xd2cfc4535cf9f7a9, 0x1b96ed84be523f2f, 0x5d7d96e085b27ab8, 0x66696c2d0706ee70, 0xd06af701961d0695, 0xe3d0c1991b1e71ad, 0x6c62932ac255fcbc, 0xd313537a398b01b7,
        0xa0b04b70cc593d5c, 0x834bf8425f299199, 0xaeecd2d380dfd0e8, 0xbead57799eac0b15, 0x540fcd9cef776f56, 0xad9576a82f49d7ca, 0xfc114ab92c99b1fa, 0x33ba36988d037738,
        0xbb26a6f4720b0273, 0xb254fd8818ce179d, 0xa6421e868f683318, 0x5fd8a5b24f568b84, 0x623e0a898ed31108, 0xb0f1cedad22ae6a1, 0x1933ded674b6ce13, 0x1416e30e97a62485,
        0x3e9f0b406e139dae, 0x6dbe0403a7270aa2, 0xbc08642b5448fa29, 0x0d253dd8e310ea96, 0x2ede8eea70604653, 0x39b1c99f485065f4, 0xcd0e4f736b7e37fe, 0xbf71c050fbdefd0b,
        0x748ddad5d391c4b1, 0x0bd7682ea021e4d2, 0x3494f447ab408f62, 0xb4a6a87e5bff19d9, 0x133821d1b1e5dcdf, 0x95f8281e026b4420, 0x2da72a91dff64171, 0x18ef49ff11c4380d,
        0xc705b074ae2d2532, 0x3de6af3bc1859a8c, 0x6835f58e4b8003c4, 0xe787a73d92cb8ed5, 0xc6d9275dcb5fd32c, 0xf7c622978cb85528, 0x4d3c134a9bc1a145, 0xf3914433056daa50,
        0xb7df0c05f4691efb, 0xe175f2cbd1fa8091, 0x77f47eae7c07c393, 0xeb7e0dcc14a9925d, 0xf1347761cf895b6c, 0x08aecc550fb7e3f0, 0x55d35ab58a059948, 0x444e4836f104b4ab,
        0x58f6676d691573de, 0x9ba4b1bd4eeda994, 0x92d6eac12428bc7a, 0xb12d59f3b75810bf, 0xa3c9ef0b63cf3a7e, 0x67b5fb046274186e, 0x2f0219c31512b04d, 0x3266a1b1e8718126,
        0x7628e9871975358d, 0xda610806534e1459, 0x311f05ca47e78604, 0x12e4b6f8d4972ac1, 0x282cdb1c33514817, 0x727f8f2390a0caf5, 0xb57a3f573e8defc7, 0x71062b583f36cdd7,
        0x84653a9d796a69c3, 0xf56311c5465ca414, 0x4737ec4d5e92b389, 0x1cb82f5b9811c775, 0x2509e6c4d041a281, 0xfdcddd9049eb47e4, 0x40192e9278d14bd3, 0x2a89e84ef9b5b92b,
        0x3631c71561a47e5e, 0x8be53417509e7269, 0x24d571edb533549f, 0xc352d6d027f8da4a, 0x01dc97296572f61e, 0xe9db3e9ede4d6361, 0x4e45b7313457a667, 0xf8462c1da54c4e82,
        0x4a12d195bd82591f, 0xff68eec2830fb6d8, 0x176f4775383023a7, 0x48b7e2c77766a823, 0x592af0440c6785c0, 0x2c7bbdb8ba84b76f, 0x5ca101c9e0c08ca6, 0x63e29da0eba1e716,
        0xd698a2f7d52c08d1, 0xce77eb08c4e830dc, 0xde366ea2da9beb21, 0x5a53543fa3f182e2, 0x52fd986aac466112, 0x86c009cfb38e98ff, 0xd1b66028f36ff08b, 0x1a4a7aaddb20c931,
        0xcfab7c21a19ac6c2, 0x09725b7c6ac515ee, 0x0e5c99a34c86edb4, 0xdbbd9f2f363ce247, 0x6a90c6dc8164f2f8, 0x8a39a33e35ec8477, 0xe0a965e2b488768f, 0x7f5ab2fb73b02063,
        0xf4bf86ec232e520a, 0xfae31f4f6fa8bfbe, 0x058bf18deca70966, 0x41c5b9bb1da3bdcd, 0x2b557f679cc74f35, 0xca208dac4d3dcfa4, 0x9a7826942b9f5f8a, 0xf0e8e048aafbad72,
        0x53210f43c934970c, 0xc1f7e582ed1c2b76, 0xc47c140f01bb2210, 0x9d56e44b0ddca7d0, 0x386d5eb62d2293ea, 0xe65b3014f7b978cb, 0x9424bf376719b23e, 0x30c392e32295701a,
    }
};

/*Таблица для операции sbox*/
static const uint8_t s_blocks[SBOX_LEN] = {
    0xa8, 0x43, 0x5f, 0x06, 0x6b, 0x75, 0x6c, 0x59, 0x71, 0xdf, 0x87, 0x95, 0x17, 0xf0, 0xd8, 0x09,
    0x6d, 0xf3, 0x1d, 0xcb, 0xc9, 0x4d, 0x2c, 0xaf, 0x79, 0xe0, 0x97, 0xfd, 0x6f, 0x4b, 0x45, 0x39,
    0x3e, 0xdd, 0xa3, 0x4f, 0xb4, 0xb6, 0x9a, 0x0e, 0x1f, 0xbf, 0x15, 0xe1, 0x49, 0xd2, 0x93, 0xc6,
    0x92, 0x72, 0x9e, 0x61, 0xd1, 0x63, 0xfa, 0xee, 0xf4, 0x19, 0xd5, 0xad, 0x58, 0xa4, 0xbb, 0xa1,
    0xdc, 0xf2, 0x83, 0x37, 0x42, 0xe4, 0x7a, 0x32, 0x9c, 0xcc, 0xab, 0x4a, 0x8f, 0x6e, 0x04, 0x27,
    0x2e, 0xe7, 0xe2, 0x5a, 0x96, 0x16, 0x23, 0x2b, 0xc2, 0x65, 0x66, 0x0f, 0xbc, 0xa9, 0x47, 0x41,
    0x34, 0x48, 0xfc, 0xb7, 0x6a, 0x88, 0xa5, 0x53, 0x86, 0xf9, 0x5b, 0xdb, 0x38, 0x7b, 0xc3, 0x1e,
    0x22, 0x33, 0x24, 0x28, 0x36, 0xc7, 0xb2, 0x3b, 0x8e, 0x77, 0xba, 0xf5, 0x14, 0x9f, 0x08, 0x55,
    0x9b, 0x4c, 0xfe, 0x60, 0x5c, 0xda, 0x18, 0x46, 0xcd, 0x7d, 0x21, 0xb0, 0x3f, 0x1b, 0x89, 0xff,
    0xeb, 0x84, 0x69, 0x3a, 0x9d, 0xd7, 0xd3, 0x70, 0x67, 0x40, 0xb5, 0xde, 0x5d, 0x30, 0x91, 0xb1,
    0x78, 0x11, 0x01, 0xe5, 0x00, 0x68, 0x98, 0xa0, 0xc5, 0x02, 0xa6, 0x74, 0x2d, 0x0b, 0xa2, 0x76,
    0xb3, 0xbe, 0xce, 0xbd, 0xae, 0xe9, 0x8a, 0x31, 0x1c, 0xec, 0xf1, 0x99, 0x94, 0xaa, 0xf6, 0x26,
    0x2f, 0xef, 0xe8, 0x8c, 0x35, 0x03, 0xd4, 0x7f, 0xfb, 0x05, 0xc1, 0x5e, 0x90, 0x20, 0x3d, 0x82,
    0xf7, 0xea, 0x0a, 0x0d, 0x7e, 0xf8, 0x50, 0x1a, 0xc4, 0x07, 0x57, 0xb8, 0x3c, 0x62, 0xe3, 0xc8,
    0xac, 0x52, 0x64, 0x10, 0xd0, 0xd9, 0x13, 0x0c, 0x12, 0x29, 0x51, 0xb9, 0xcf, 0xd6, 0x73, 0x8d,
    0x81, 0x54, 0xc0, 0xed, 0x4e, 0x44, 0xa7, 0x2a, 0x85, 0x25, 0xe6, 0xca, 0x7c, 0x8b, 0x56, 0x80,

    0xce, 0xbb, 0xeb, 0x92, 0xea, 0xcb, 0x13, 0xc1, 0xe9, 0x3a, 0xd6, 0xb2, 0xd2, 0x90, 0x17, 0xf8,
    0x42, 0x15, 0x56, 0xb4, 0x65, 0x1c, 0x88, 0x43, 0xc5, 0x5c, 0x36, 0xba, 0xf5, 0x57, 0x67, 0x8d,
    0x31, 0xf6, 0x64, 0x58, 0x9e, 0xf4, 0x22, 0xaa, 0x75, 0x0f, 0x02, 0xb1, 0xdf, 0x6d, 0x73, 0x4d,
    0x7c, 0x26, 0x2e, 0xf7, 0x08, 0x5d, 0x44, 0x3e, 0x9f, 0x14, 0xc8, 0xae, 0x54, 0x10, 0xd8, 0xbc,
    0x1a, 0x6b, 0x69, 0xf3, 0xbd, 0x33, 0xab, 0xfa, 0xd1, 0x9b, 0x68, 0x4e, 0x16, 0x95, 0x91, 0xee,
    0x4c, 0x63, 0x8e, 0x5b, 0xcc, 0x3c, 0x19, 0xa1, 0x81, 0x49, 0x7b, 0xd9, 0x6f, 0x37, 0x60, 0xca,
    0xe7, 0x2b, 0x48, 0xfd, 0x96, 0x45, 0xfc, 0x41, 0x12, 0x0d, 0x79, 0xe5, 0x89, 0x8c, 0xe3, 0x20,
    0x30, 0xdc, 0xb7, 0x6c, 0x4a, 0xb5, 0x3f, 0x97, 0xd4, 0x62, 0x2d, 0x06, 0xa4, 0xa5, 0x83, 0x5f,
    0x2a, 0xda, 0xc9, 0x00, 0x7e, 0xa2, 0x55, 0xbf, 0x11, 0xd5, 0x9c, 0xcf, 0x0e, 0x0a, 0x3d, 0x51,
    0x7d, 0x93, 0x1b, 0xfe, 0xc4, 0x47, 0x09, 0x86, 0x0b, 0x8f, 0x9d, 0x6a, 0x07, 0xb9, 0xb0, 0x98,
    0x18, 0x32, 0x71, 0x4b, 0xef, 0x3b, 0x70, 0xa0, 0xe4, 0x40, 0xff, 0xc3, 0xa9, 0xe6, 0x78, 0xf9,
    0x8b, 0x46, 0x80, 0x1e, 0x38, 0xe1, 0xb8, 0xa8, 0xe0, 0x0c, 0x23, 0x76, 0x1d, 0x25, 0x24, 0x05,
    0xf1, 0x6e, 0x94, 0x28, 0x9a, 0x84, 0xe8, 0xa3, 0x4f, 0x77, 0xd3, 0x85, 0xe2, 0x52, 0xf2, 0x82,
    0x50, 0x7a, 0x2f, 0x74, 0x53, 0xb3, 0x61, 0xaf, 0x39, 0x35, 0xde, 0xcd, 0x1f, 0x99, 0xac, 0xad,
    0x72, 0x2c, 0xdd, 0xd0, 0x87, 0xbe, 0x5e, 0xa6, 0xec, 0x04, 0xc6, 0x03, 0x34, 0xfb, 0xdb, 0x59,
    0xb6, 0xc2, 0x01, 0xf0, 0x5a, 0xed, 0xa7, 0x66, 0x21, 0x7f, 0x8a, 0x27, 0xc7, 0xc0, 0x29, 0xd7,

    0x93, 0xd9, 0x9a, 0xb5, 0x98, 0x22, 0x45, 0xfc, 0xba, 0x6a, 0xdf, 0x02, 0x9f, 0xdc, 0x51, 0x59,
    0x4a, 0x17, 0x2b, 0xc2, 0x94, 0xf4, 0xbb, 0xa3, 0x62, 0xe4, 0x71, 0xd4, 0xcd, 0x70, 0x16, 0xe1,
    0x49, 0x3c, 0xc0, 0xd8, 0x5c, 0x9b, 0xad, 0x85, 0x53, 0xa1, 0x7a, 0xc8, 0x2d, 0xe0, 0xd1, 0x72,
    0xa6, 0x2c, 0xc4, 0xe3, 0x76, 0x78, 0xb7, 0xb4, 0x09, 0x3b, 0x0e, 0x41, 0x4c, 0xde, 0xb2, 0x90,
    0x25, 0xa5, 0xd7, 0x03, 0x11, 0x00, 0xc3, 0x2e, 0x92, 0xef, 0x4e, 0x12, 0x9d, 0x7d, 0xcb, 0x35,
    0x10, 0xd5, 0x4f, 0x9e, 0x4d, 0xa9, 0x55, 0xc6, 0xd0, 0x7b, 0x18, 0x97, 0xd3, 0x36, 0xe6, 0x48,
    0x56, 0x81, 0x8f, 0x77, 0xcc, 0x9c, 0xb9, 0xe2, 0xac, 0xb8, 0x2f, 0x15, 0xa4, 0x7c, 0xda, 0x38,
    0x1e, 0x0b, 0x05, 0xd6, 0x14, 0x6e, 0x6c, 0x7e, 0x66, 0xfd, 0xb1, 0xe5, 0x60, 0xaf, 0x5e, 0x33,
    0x87, 0xc9, 0xf0, 0x5d, 0x6d, 0x3f, 0x88, 0x8d, 0xc7, 0xf7, 0x1d, 0xe9, 0xec, 0xed, 0x80, 0x29,
    0x27, 0xcf, 0x99, 0xa8, 0x50, 0x0f, 0x37, 0x24, 0x28, 0x30, 0x95, 0xd2, 0x3e, 0x5b, 0x40, 0x83,
    0xb3, 0x69, 0x57, 0x1f, 0x07, 0x1c, 0x8a, 0xbc, 0x20, 0xeb, 0xce, 0x8e, 0xab, 0xee, 0x31, 0xa2,
    0x73, 0xf9, 0xca, 0x3a, 0x1a, 0xfb, 0x0d, 0xc1, 0xfe, 0xfa, 0xf2, 0x6f, 0xbd, 0x96, 0xdd, 0x43,
    0x52, 0xb6, 0x08, 0xf3, 0xae, 0xbe, 0x19, 0x89, 0x32, 0x26, 0xb0, 0xea, 0x4b, 0x64, 0x84, 0x82,
    0x6b, 0xf5, 0x79, 0xbf, 0x01, 0x5f, 0x75, 0x63, 0x1b, 0x23, 0x3d, 0x68, 0x2a, 0x65, 0xe8, 0x91,
    0xf6, 0xff, 0x13, 0x58, 0xf1, 0x47, 0x0a, 0x7f, 0xc5, 0xa7, 0xe7, 0x61, 0x5a, 0x06, 0x46, 0x44,
    0x42, 0x04, 0xa0, 0xdb, 0x39, 0x86, 0x54, 0xaa, 0x8c, 0x34, 0x21, 0x8b, 0xf8, 0x0c, 0x74, 0x67,

    0x68, 0x8d, 0xca, 0x4d, 0x73, 0x4b, 0x4e, 0x2a, 0xd4, 0x52, 0x26, 0xb3, 0x54, 0x1e, 0x19, 0x1f,
    0x22, 0x03, 0x46, 0x3d, 0x2d, 0x4a, 0x53, 0x83, 0x13, 0x8a, 0xb7, 0xd5, 0x25, 0x79, 0xf5, 0xbd,
    0x58, 0x2f, 0x0d, 0x02, 0xed, 0x51, 0x9e, 0x11, 0xf2, 0x3e, 0x55, 0x5e, 0xd1, 0x16, 0x3c, 0x66,
    0x70, 0x5d, 0xf3, 0x45, 0x40, 0xcc, 0xe8, 0x94, 0x56, 0x08, 0xce, 0x1a, 0x3a, 0xd2, 0xe1, 0xdf,
    0xb5, 0x38, 0x6e, 0x0e, 0xe5, 0xf4, 0xf9, 0x86, 0xe9, 0x4f, 0xd6, 0x85, 0x23, 0xcf, 0x32, 0x99,
    0x31, 0x14, 0xae, 0xee, 0xc8, 0x48, 0xd3, 0x30, 0xa1, 0x92, 0x41, 0xb1, 0x18, 0xc4, 0x2c, 0x71,
    0x72, 0x44, 0x15, 0xfd, 0x37, 0xbe, 0x5f, 0xaa, 0x9b, 0x88, 0xd8, 0xab, 0x89, 0x9c, 0xfa, 0x60,
    0xea, 0xbc, 0x62, 0x0c, 0x24, 0xa6, 0xa8, 0xec, 0x67, 0x20, 0xdb, 0x7c, 0x28, 0xdd, 0xac, 0x5b,
    0x34, 0x7e, 0x10, 0xf1, 0x7b, 0x8f, 0x63, 0xa0, 0x05, 0x9a, 0x43, 0x77, 0x21, 0xbf, 0x27, 0x09,
    0xc3, 0x9f, 0xb6, 0xd7, 0x29, 0xc2, 0xeb, 0xc0, 0xa4, 0x8b, 0x8c, 0x1d, 0xfb, 0xff, 0xc1, 0xb2,
    0x97, 0x2e, 0xf8, 0x65, 0xf6, 0x75, 0x07, 0x04, 0x49, 0x33, 0xe4, 0xd9, 0xb9, 0xd0, 0x42, 0xc7,
    0x6c, 0x90, 0x00, 0x8e, 0x6f, 0x50, 0x01, 0xc5, 0xda, 0x47, 0x3f, 0xcd, 0x69, 0xa2, 0xe2, 0x7a,
    0xa7, 0xc6, 0x93, 0x0f, 0x0a, 0x06, 0xe6, 0x2b, 0x96, 0xa3, 0x1c, 0xaf, 0x6a, 0x12, 0x84, 0x39,
    0xe7, 0xb0, 0x82, 0xf7, 0xfe, 0x9d, 0x87, 0x5c, 0x81, 0x35, 0xde, 0xb4, 0xa5, 0xfc, 0x80, 0xef,
    0xcb, 0xbb, 0x6b, 0x76, 0xba, 0x5a, 0x7d, 0x78, 0x0b, 0x95, 0xe3, 0xad, 0x74, 0x98, 0x3b, 0x36,
    0x64, 0x6d, 0xdc, 0xf0, 0x59, 0xa9, 0x4c, 0x17, 0x7f, 0x91, 0xb8, 0xc9, 0x57, 0x1b, 0xe0, 0x61
};

/*Таблица для операции sbox_inv*/
static const uint8_t s_blocks_reverse[SBOX_LEN] = {
    0xA4, 0xA2, 0xA9, 0xC5, 0x4E, 0xC9, 0x03, 0xD9, 0x7E, 0x0F, 0xD2, 0xAD, 0xE7, 0xD3, 0x27, 0x5B,
    0xE3, 0xA1, 0xE8, 0xE6, 0x7C, 0x2A, 0x55, 0x0C, 0x86, 0x39, 0xD7, 0x8D, 0xB8, 0x12, 0x6F, 0x28,
    0xCD, 0x8A, 0x70, 0x56, 0x72, 0xF9, 0xBF, 0x4F, 0x73, 0xE9, 0xF7, 0x57, 0x16, 0xAC, 0x50, 0xC0,
    0x9D, 0xB7, 0x47, 0x71, 0x60, 0xC4, 0x74, 0x43, 0x6C, 0x1F, 0x93, 0x77, 0xDC, 0xCE, 0x20, 0x8C,
    0x99, 0x5F, 0x44, 0x01, 0xF5, 0x1E, 0x87, 0x5E, 0x61, 0x2C, 0x4B, 0x1D, 0x81, 0x15, 0xF4, 0x23,
    0xD6, 0xEA, 0xE1, 0x67, 0xF1, 0x7F, 0xFE, 0xDA, 0x3C, 0x07, 0x53, 0x6A, 0x84, 0x9C, 0xCB, 0x02,
    0x83, 0x33, 0xDD, 0x35, 0xE2, 0x59, 0x5A, 0x98, 0xA5, 0x92, 0x64, 0x04, 0x06, 0x10, 0x4D, 0x1C,
    0x97, 0x08, 0x31, 0xEE, 0xAB, 0x05, 0xAF, 0x79, 0xA0, 0x18, 0x46, 0x6D, 0xFC, 0x89, 0xD4, 0xC7,
    0xFF, 0xF0, 0xCF, 0x42, 0x91, 0xF8, 0x68, 0x0A, 0x65, 0x8E, 0xB6, 0xFD, 0xC3, 0xEF, 0x78, 0x4C,
    0xCC, 0x9E, 0x30, 0x2E, 0xBC, 0x0B, 0x54, 0x1A, 0xA6, 0xBB, 0x26, 0x80, 0x48, 0x94, 0x32, 0x7D,
    0xA7, 0x3F, 0xAE, 0x22, 0x3D, 0x66, 0xAA, 0xF6, 0x00, 0x5D, 0xBD, 0x4A, 0xE0, 0x3B, 0xB4, 0x17,
    0x8B, 0x9F, 0x76, 0xB0, 0x24, 0x9A, 0x25, 0x63, 0xDB, 0xEB, 0x7A, 0x3E, 0x5C, 0xB3, 0xB1, 0x29,
    0xF2, 0xCA, 0x58, 0x6E, 0xD8, 0xA8, 0x2F, 0x75, 0xDF, 0x14, 0xFB, 0x13, 0x49, 0x88, 0xB2, 0xEC,
    0xE4, 0x34, 0x2D, 0x96, 0xC6, 0x3A, 0xED, 0x95, 0x0E, 0xE5, 0x85, 0x6B, 0x40, 0x21, 0x9B, 0x09,
    0x19, 0x2B, 0x52, 0xDE, 0x45, 0xA3, 0xFA, 0x51, 0xC2, 0xB5, 0xD1, 0x90, 0xB9, 0xF3, 0x37, 0xC1,
    0x0D, 0xBA, 0x41, 0x11, 0x38, 0x7B, 0xBE, 0xD0, 0xD5, 0x69, 0x36, 0xC8, 0x62, 0x1B, 0x82, 0x8F,

    0x83, 0xF2, 0x2A, 0xEB, 0xE9, 0xBF, 0x7B, 0x9C, 0x34, 0x96, 0x8D, 0x98, 0xB9, 0x69, 0x8C, 0x29,
    0x3D, 0x88, 0x68, 0x06, 0x39, 0x11, 0x4C, 0x0E, 0xA0, 0x56, 0x40, 0x92, 0x15, 0xBC, 0xB3, 0xDC,
    0x6F, 0xF8, 0x26, 0xBA, 0xBE, 0xBD, 0x31, 0xFB, 0xC3, 0xFE, 0x80, 0x61, 0xE1, 0x7A, 0x32, 0xD2,
    0x70, 0x20, 0xA1, 0x45, 0xEC, 0xD9, 0x1A, 0x5D, 0xB4, 0xD8, 0x09, 0xA5, 0x55, 0x8E, 0x37, 0x76,
    0xA9, 0x67, 0x10, 0x17, 0x36, 0x65, 0xB1, 0x95, 0x62, 0x59, 0x74, 0xA3, 0x50, 0x2F, 0x4B, 0xC8,
    0xD0, 0x8F, 0xCD, 0xD4, 0x3C, 0x86, 0x12, 0x1D, 0x23, 0xEF, 0xF4, 0x53, 0x19, 0x35, 0xE6, 0x7F,
    0x5E, 0xD6, 0x79, 0x51, 0x22, 0x14, 0xF7, 0x1E, 0x4A, 0x42, 0x9B, 0x41, 0x73, 0x2D, 0xC1, 0x5C,
    0xA6, 0xA2, 0xE0, 0x2E, 0xD3, 0x28, 0xBB, 0xC9, 0xAE, 0x6A, 0xD1, 0x5A, 0x30, 0x90, 0x84, 0xF9,
    0xB2, 0x58, 0xCF, 0x7E, 0xC5, 0xCB, 0x97, 0xE4, 0x16, 0x6C, 0xFA, 0xB0, 0x6D, 0x1F, 0x52, 0x99,
    0x0D, 0x4E, 0x03, 0x91, 0xC2, 0x4D, 0x64, 0x77, 0x9F, 0xDD, 0xC4, 0x49, 0x8A, 0x9A, 0x24, 0x38,
    0xA7, 0x57, 0x85, 0xC7, 0x7C, 0x7D, 0xE7, 0xF6, 0xB7, 0xAC, 0x27, 0x46, 0xDE, 0xDF, 0x3B, 0xD7,
    0x9E, 0x2B, 0x0B, 0xD5, 0x13, 0x75, 0xF0, 0x72, 0xB6, 0x9D, 0x1B, 0x01, 0x3F, 0x44, 0xE5, 0x87,
    0xFD, 0x07, 0xF1, 0xAB, 0x94, 0x18, 0xEA, 0xFC, 0x3A, 0x82, 0x5F, 0x05, 0x54, 0xDB, 0x00, 0x8B,
    0xE3, 0x48, 0x0C, 0xCA, 0x78, 0x89, 0x0A, 0xFF, 0x3E, 0x5B, 0x81, 0xEE, 0x71, 0xE2, 0xDA, 0x2C,
    0xB8, 0xB5, 0xCC, 0x6E, 0xA8, 0x6B, 0xAD, 0x60, 0xC6, 0x08, 0x04, 0x02, 0xE8, 0xF5, 0x4F, 0xA4,
    0xF3, 0xC0, 0xCE, 0x43, 0x25, 0x1C, 0x21, 0x33, 0x0F, 0xAF, 0x47, 0xED, 0x66, 0x63, 0x93, 0xAA,

    0x45, 0xD4, 0x0B, 0x43, 0xF1, 0x72, 0xED, 0xA4, 0xC2, 0x38, 0xE6, 0x71, 0xFD, 0xB6, 0x3A, 0x95,
    0x50, 0x44, 0x4B, 0xE2, 0x74, 0x6B, 0x1E, 0x11, 0x5A, 0xC6, 0xB4, 0xD8, 0xA5, 0x8A, 0x70, 0xA3,
    0xA8, 0xFA, 0x05, 0xD9, 0x97, 0x40, 0xC9, 0x90, 0x98, 0x8F, 0xDC, 0x12, 0x31, 0x2C, 0x47, 0x6A,
    0x99, 0xAE, 0xC8, 0x7F, 0xF9, 0x4F, 0x5D, 0x96, 0x6F, 0xF4, 0xB3, 0x39, 0x21, 0xDA, 0x9C, 0x85,
    0x9E, 0x3B, 0xF0, 0xBF, 0xEF, 0x06, 0xEE, 0xE5, 0x5F, 0x20, 0x10, 0xCC, 0x3C, 0x54, 0x4A, 0x52,
    0x94, 0x0E, 0xC0, 0x28, 0xF6, 0x56, 0x60, 0xA2, 0xE3, 0x0F, 0xEC, 0x9D, 0x24, 0x83, 0x7E, 0xD5,
    0x7C, 0xEB, 0x18, 0xD7, 0xCD, 0xDD, 0x78, 0xFF, 0xDB, 0xA1, 0x09, 0xD0, 0x76, 0x84, 0x75, 0xBB,
    0x1D, 0x1A, 0x2F, 0xB0, 0xFE, 0xD6, 0x34, 0x63, 0x35, 0xD2, 0x2A, 0x59, 0x6D, 0x4D, 0x77, 0xE7,
    0x8E, 0x61, 0xCF, 0x9F, 0xCE, 0x27, 0xF5, 0x80, 0x86, 0xC7, 0xA6, 0xFB, 0xF8, 0x87, 0xAB, 0x62,
    0x3F, 0xDF, 0x48, 0x00, 0x14, 0x9A, 0xBD, 0x5B, 0x04, 0x92, 0x02, 0x25, 0x65, 0x4C, 0x53, 0x0C,
    0xF2, 0x29, 0xAF, 0x17, 0x6C, 0x41, 0x30, 0xE9, 0x93, 0x55, 0xF7, 0xAC, 0x68, 0x26, 0xC4, 0x7D,
    0xCA, 0x7A, 0x3E, 0xA0, 0x37, 0x03, 0xC1, 0x36, 0x69, 0x66, 0x08, 0x16, 0xA7, 0xBC, 0xC5, 0xD3,
    0x22, 0xB7, 0x13, 0x46, 0x32, 0xE8, 0x57, 0x88, 0x2B, 0x81, 0xB2, 0x4E, 0x64, 0x1C, 0xAA, 0x91,
    0x58, 0x2E, 0x9B, 0x5C, 0x1B, 0x51, 0x73, 0x42, 0x23, 0x01, 0x6E, 0xF3, 0x0D, 0xBE, 0x3D, 0x0A,
    0x2D, 0x1F, 0x67, 0x33, 0x19, 0x7B, 0x5E, 0xEA, 0xDE, 0x8B, 0xCB, 0xA9, 0x8C, 0x8D, 0xAD, 0x49,
    0x82, 0xE4, 0xBA, 0xC3, 0x15, 0xD1, 0xE0, 0x89, 0xFC, 0xB1, 0xB9, 0xB5, 0x07, 0x79, 0xB8, 0xE1,

    0xB2, 0xB6, 0x23, 0x11, 0xA7, 0x88, 0xC5, 0xA6, 0x39, 0x8F, 0xC4, 0xE8, 0x73, 0x22, 0x43, 0xC3,
    0x82, 0x27, 0xCD, 0x18, 0x51, 0x62, 0x2D, 0xF7, 0x5C, 0x0E, 0x3B, 0xFD, 0xCA, 0x9B, 0x0D, 0x0F,
    0x79, 0x8C, 0x10, 0x4C, 0x74, 0x1C, 0x0A, 0x8E, 0x7C, 0x94, 0x07, 0xC7, 0x5E, 0x14, 0xA1, 0x21,
    0x57, 0x50, 0x4E, 0xA9, 0x80, 0xD9, 0xEF, 0x64, 0x41, 0xCF, 0x3C, 0xEE, 0x2E, 0x13, 0x29, 0xBA,
    0x34, 0x5A, 0xAE, 0x8A, 0x61, 0x33, 0x12, 0xB9, 0x55, 0xA8, 0x15, 0x05, 0xF6, 0x03, 0x06, 0x49,
    0xB5, 0x25, 0x09, 0x16, 0x0C, 0x2A, 0x38, 0xFC, 0x20, 0xF4, 0xE5, 0x7F, 0xD7, 0x31, 0x2B, 0x66,
    0x6F, 0xFF, 0x72, 0x86, 0xF0, 0xA3, 0x2F, 0x78, 0x00, 0xBC, 0xCC, 0xE2, 0xB0, 0xF1, 0x42, 0xB4,
    0x30, 0x5F, 0x60, 0x04, 0xEC, 0xA5, 0xE3, 0x8B, 0xE7, 0x1D, 0xBF, 0x84, 0x7B, 0xE6, 0x81, 0xF8,
    0xDE, 0xD8, 0xD2, 0x17, 0xCE, 0x4B, 0x47, 0xD6, 0x69, 0x6C, 0x19, 0x99, 0x9A, 0x01, 0xB3, 0x85,
    0xB1, 0xF9, 0x59, 0xC2, 0x37, 0xE9, 0xC8, 0xA0, 0xED, 0x4F, 0x89, 0x68, 0x6D, 0xD5, 0x26, 0x91,
    0x87, 0x58, 0xBD, 0xC9, 0x98, 0xDC, 0x75, 0xC0, 0x76, 0xF5, 0x67, 0x6B, 0x7E, 0xEB, 0x52, 0xCB,
    0xD1, 0x5B, 0x9F, 0x0B, 0xDB, 0x40, 0x92, 0x1A, 0xFA, 0xAC, 0xE4, 0xE1, 0x71, 0x1F, 0x65, 0x8D,
    0x97, 0x9E, 0x95, 0x90, 0x5D, 0xB7, 0xC1, 0xAF, 0x54, 0xFB, 0x02, 0xE0, 0x35, 0xBB, 0x3A, 0x4D,
    0xAD, 0x2C, 0x3D, 0x56, 0x08, 0x1B, 0x4A, 0x93, 0x6A, 0xAB, 0xB8, 0x7A, 0xF2, 0x7D, 0xDA, 0x3F,
    0xFE, 0x3E, 0xBE, 0xEA, 0xAA, 0x44, 0xC6, 0xD0, 0x36, 0x48, 0x70, 0x96, 0x77, 0x24, 0x53, 0xDF,
    0xF3, 0x83, 0x28, 0x32, 0x45, 0x1E, 0xA4, 0xD3, 0xA2, 0x46, 0x6E, 0x9C, 0xDD, 0x63, 0xD4, 0x9D
};

/*Russian peasant multiplication algorithm*/
static uint8_t multiply_galua(uint8_t x, uint8_t y)
{
    int i;
    uint8_t r = 0;
    uint8_t hbit = 0;
    for (i = 0; i < BITS_IN_BYTE; ++i) {
        if ((y & 0x1) == 1) {
            r ^= x;
        }
        hbit = (uint8_t) (x & 0x80);
        x <<= 1;
        if (hbit == 0x80) {
            x ^= REDUCTION_POLYNOMIAL;
        }
        y >>= 1;
    }
    return r;
}

static void generate_reverse_table(const uint8_t *s_blocks, uint8_t *s_blocks_rev)
{
    size_t i, j;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < MAX_NUM_IN_BYTE; j++) {
            s_blocks_rev[i * MAX_NUM_IN_BYTE + s_blocks[i * MAX_NUM_IN_BYTE + j]] = (uint8_t) j;
        }
    }
}

/*Precompute sbox and srow operations*/
static void p_sub_row_col(const uint8_t *s_blocks, uint64_t p_boxrowcol[ROWS][MAX_NUM_IN_BYTE],
        const uint8_t *mds_matrix)
{
    size_t i, k;

    for (k = 0; k < ROWS; k++) {
        for (i = 0; i < MAX_NUM_IN_BYTE; i++) {
            p_boxrowcol[k][i] = GALUA_MUL(i, 0, k, 0) ^ GALUA_MUL(i, 1, k, 8) ^ GALUA_MUL(i, 2, k, 16) ^ GALUA_MUL(i, 3, k, 24) ^
                    GALUA_MUL(i, 4, k, 32) ^ GALUA_MUL(i, 5, k, 40) ^ GALUA_MUL(i, 6, k, 48) ^ GALUA_MUL(i, 7, k, 56);
        }
    }
}

static void crypt_basic_transform(Dstu7624Ctx *ctx, const uint8_t *plain_data, uint8_t *cipher_data)
{
    uint64_t state[8] = {0};
    uint8_to_uint64(plain_data, ctx->block_len, state, ctx->block_len >> 3);

    ctx->basic_transform(ctx, state);

    uint64_to_uint8(state, ctx->block_len >> 3, cipher_data, ctx->block_len);
}

Dstu7624Ctx *dstu7624_alloc(Dstu7624SboxId sbox_id)
{
    int ret = RET_OK;
    Dstu7624Ctx *ctx = NULL;

    CALLOC_CHECKED(ctx, sizeof(Dstu7624Ctx));

    switch (sbox_id) {
    case DSTU7624_SBOX_1:
        memcpy(ctx->sbox, s_blocks, SBOX_LEN);
        memcpy(ctx->sbox_rev, s_blocks_reverse, SBOX_LEN);
        memcpy(ctx->p_boxrowcol, subrowcol, 8 * 256 * sizeof(uint64_t));
        memcpy(ctx->p_boxrowcol_rev, subrowcol_dec, 8 * 256 * sizeof(uint64_t));
        break;
    default:
        ERROR_CREATE(RET_INVALID_PARAM);
    }

cleanup:

    return ctx;
}

static Dstu7624Ctx *dstu7624_alloc_user_sbox_core(const uint8_t *s_blocks, size_t sbox_len)
{
    Dstu7624Ctx *ctx = NULL;
    int ret = RET_OK;

    CHECK_PARAM(s_blocks != NULL);
    CHECK_PARAM(sbox_len == SBOX_LEN);

    CALLOC_CHECKED(ctx, sizeof (Dstu7624Ctx));

    memcpy(ctx->sbox, s_blocks, SBOX_LEN);
    p_sub_row_col(s_blocks, ctx->p_boxrowcol, mds_matrix);
    generate_reverse_table(s_blocks, ctx->sbox_rev);
    p_sub_row_col(ctx->sbox_rev, ctx->p_boxrowcol_rev, mds_matrix_reverse);

cleanup:

    return ctx;
}

Dstu7624Ctx *dstu7624_alloc_user_sbox(ByteArray *sblocks)
{
    Dstu7624Ctx *ctx = NULL;
    uint8_t *sblocks_buf = NULL;
    size_t sblock_len;
    int ret = RET_OK;

    CHECK_PARAM(sblocks != NULL);
    DO(ba_to_uint8_with_alloc(sblocks, &sblocks_buf, &sblock_len));

    CHECK_NOT_NULL(ctx = dstu7624_alloc_user_sbox_core(sblocks_buf, sblock_len));
cleanup:
    free(sblocks_buf);
    return ctx;
}

void dstu7624_free(Dstu7624Ctx *ctx)
{
    if (ctx) {
        switch (ctx->mode_id) {
        case DSTU7624_MODE_CTR:
            break;
        case DSTU7624_MODE_CBC:
            break;
        case DSTU7624_MODE_OFB:
            break;
        case DSTU7624_MODE_CFB:
            break;
        case DSTU7624_MODE_CCM:
            break;
        case DSTU7624_MODE_CMAC:
            break;
        case DSTU7624_MODE_XTS:
            gf2m_free(ctx->mode.xts.gf2m_ctx);
            break;
        case DSTU7624_MODE_GCM:
            gf2m_free(ctx->mode.gcm.gf2m_ctx);
            break;
        case DSTU7624_MODE_GMAC:
            gf2m_free(ctx->mode.gmac.gf2m_ctx);
            break;
        default:
            break;
        }
        secure_zero(ctx, sizeof (Dstu7624Ctx));
        free(ctx);
    }
}

int dstu7624_generate_key(PrngCtx *prng, size_t key_len, ByteArray **key)
{
    int ret = RET_OK;

    CHECK_PARAM(key_len == 16 || key_len == 32 || key_len == 64)

    CHECK_NOT_NULL(*key = ba_alloc_by_len(key_len));
    DO(prng_next_bytes(prng, *key));

cleanup:

    return ret;
}

static __inline void basic_transform_128(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[2] = {0, 0};
    uint64_t *rkey = (uint64_t *) ctx->p_rkeys;

    state[0] += rkey[0];
    state[1] += rkey[1];
    BT_xor128(state, point, rkey + 2);
    BT_xor128(point, state, rkey + 4);
    BT_xor128(state, point, rkey + 6);
    BT_xor128(point, state, rkey + 8);
    BT_xor128(state, point, rkey + 10);
    BT_xor128(point, state, rkey + 12);
    BT_xor128(state, point, rkey + 14);
    BT_xor128(point, state, rkey + 16);
    BT_xor128(state, point, rkey + 18);
    BT_add128(point, state, rkey + 20);
}

static __inline void basic_transform_128_256(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[2] = {0, 0};
    uint64_t *rkey = (uint64_t *) ctx->p_rkeys;

    state[0] += rkey[0];
    state[1] += rkey[1];
    BT_xor128(state, point, rkey + 2);
    BT_xor128(point, state, rkey + 4);
    BT_xor128(state, point, rkey + 6);
    BT_xor128(point, state, rkey + 8);
    BT_xor128(state, point, rkey + 10);
    BT_xor128(point, state, rkey + 12);
    BT_xor128(state, point, rkey + 14);
    BT_xor128(point, state, rkey + 16);
    BT_xor128(state, point, rkey + 18);
    BT_xor128(point, state, rkey + 20);
    BT_xor128(state, point, rkey + 22);
    BT_xor128(point, state, rkey + 24);
    BT_xor128(state, point, rkey + 26);
    BT_add128(point, state, rkey + 28);
}

static __inline void basic_transform_256(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[4] = {0, 0, 0, 0};
    uint64_t *rkey = (uint64_t *) ctx->p_rkeys;

    state[0] += rkey[0];
    state[1] += rkey[1];
    state[2] += rkey[2];
    state[3] += rkey[3];
    BT_xor256(state, point, rkey + 4);
    BT_xor256(point, state, rkey + 8);
    BT_xor256(state, point, rkey + 12);
    BT_xor256(point, state, rkey + 16);
    BT_xor256(state, point, rkey + 20);
    BT_xor256(point, state, rkey + 24);
    BT_xor256(state, point, rkey + 28);
    BT_xor256(point, state, rkey + 32);
    BT_xor256(state, point, rkey + 36);
    BT_xor256(point, state, rkey + 40);
    BT_xor256(state, point, rkey + 44);
    BT_xor256(point, state, rkey + 48);
    BT_xor256(state, point, rkey + 52);
    BT_add256(point, state, rkey + 56);
}

static __inline void basic_transform_256_512(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[4] = {0, 0, 0, 0};
    uint64_t *rkey = (uint64_t *) ctx->p_rkeys;

    state[0] += rkey[0];
    state[1] += rkey[1];
    state[2] += rkey[2];
    state[3] += rkey[3];
    BT_xor256(state, point, rkey + 4);
    BT_xor256(point, state, rkey + 8);
    BT_xor256(state, point, rkey + 12);
    BT_xor256(point, state, rkey + 16);
    BT_xor256(state, point, rkey + 20);
    BT_xor256(point, state, rkey + 24);
    BT_xor256(state, point, rkey + 28);
    BT_xor256(point, state, rkey + 32);
    BT_xor256(state, point, rkey + 36);
    BT_xor256(point, state, rkey + 40);
    BT_xor256(state, point, rkey + 44);
    BT_xor256(point, state, rkey + 48);
    BT_xor256(state, point, rkey + 52);
    BT_xor256(point, state, rkey + 56);
    BT_xor256(state, point, rkey + 60);
    BT_xor256(point, state, rkey + 64);
    BT_xor256(state, point, rkey + 68);
    BT_add256(point, state, rkey + 72);
}

static __inline void basic_transform_512(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t *rkey = ctx->p_rkeys;

    state[0] += rkey[0];
    state[1] += rkey[1];
    state[2] += rkey[2];
    state[3] += rkey[3];
    state[4] += rkey[4];
    state[5] += rkey[5];
    state[6] += rkey[6];
    state[7] += rkey[7];

    BT_xor512(state, point, &rkey[8]);
    BT_xor512(point, state, rkey + 16);
    BT_xor512(state, point, rkey + 24);
    BT_xor512(point, state, rkey + 32);
    BT_xor512(state, point, rkey + 40);
    BT_xor512(point, state, rkey + 48);
    BT_xor512(state, point, rkey + 56);
    BT_xor512(point, state, rkey + 64);
    BT_xor512(state, point, rkey + 72);
    BT_xor512(point, state, rkey + 80);
    BT_xor512(state, point, rkey + 88);
    BT_xor512(point, state, rkey + 96);
    BT_xor512(state, point, rkey + 104);
    BT_xor512(point, state, rkey + 112);
    BT_xor512(state, point, rkey + 120);
    BT_xor512(point, state, rkey + 128);
    BT_xor512(state, point, rkey + 136);
    BT_add512(point, state, rkey + 144);
}

static __inline void subrowcol128(uint64_t *state, Dstu7624Ctx *ctx)
{
    uint64_t point[2] = {0, 0};
    kalina_G128(ctx->p_boxrowcol, state, point, 0, 0, 0, 0, 1, 1, 1, 1);
    memcpy(state, point, ctx->block_len);
}

static __inline void subrowcol256(uint64_t *state, Dstu7624Ctx *ctx)
{
    uint64_t point[4] = {0, 0, 0, 0};
    kalina_G256(ctx->p_boxrowcol, state, point, 0, 0, 3, 3, 2, 2, 1, 1);
    memcpy(state, point, ctx->block_len);
}

static __inline void subrowcol512(uint64_t *state, Dstu7624Ctx *ctx)
{
    uint64_t point[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    kalina_G512(ctx->p_boxrowcol, state, point, 0, 7, 6, 5, 4, 3, 2, 1);
    memcpy(state, point, ctx->block_len);
}

__inline static void inv_subrowcol_xor128(const uint64_t *state, uint64_t *out, const uint64_t *rkey,
        uint64_t boxrowcol[8][256])
{
    uint64_t s0 = state[0];
    uint64_t s1 = state[1];
    out[0] = rkey[0] ^
            boxrowcol[0][s0 & 255] ^
            boxrowcol[1][(s0 >> 8) & 255] ^
            boxrowcol[2][(s0 >> 16) & 255] ^
            boxrowcol[3][(s0 >> 24) & 255] ^
            boxrowcol[4][(s1 >> 32) & 255] ^
            boxrowcol[5][(s1 >> 40) & 255] ^
            boxrowcol[6][(s1 >> 48) & 255] ^
            boxrowcol[7][(s1 >> 56) & 255];
    out[1] = rkey[1] ^
            boxrowcol[0][s1 & 255] ^
            boxrowcol[1][(s1 >> 8) & 255] ^
            boxrowcol[2][(s1 >> 16) & 255] ^
            boxrowcol[3][(s1 >> 24) & 255] ^
            boxrowcol[4][(s0 >> 32) & 255] ^
            boxrowcol[5][(s0 >> 40) & 255] ^
            boxrowcol[6][(s0 >> 48) & 255] ^
            boxrowcol[7][(s0 >> 56) & 255];
}

__inline static void inv_subrowcol_xor256(const uint64_t *state, uint64_t *out, const uint64_t *rkey,
        uint64_t boxrowcol[8][256])
{
    uint64_t s0 = state[0];
    uint64_t s1 = state[1];
    uint64_t s2 = state[2];
    uint64_t s3 = state[3];
    out[0] = rkey[0] ^ boxrowcol[0][s0 & 255] ^
            boxrowcol[1][((s0 >> 8) & 255)] ^
            boxrowcol[2][((s1 >> 16) & 255)] ^
            boxrowcol[3][((s1 >> 24) & 255)] ^
            boxrowcol[4][((s2 >> 32) & 255)] ^
            boxrowcol[5][((s2 >> 40) & 255)] ^
            boxrowcol[6][((s3 >> 48) & 255)] ^
            boxrowcol[7][((s3 >> 56) & 255)];
    out[1] = rkey[1] ^ boxrowcol[0][s1 & 255] ^
            boxrowcol[1][((s1 >> 8) & 255)] ^
            boxrowcol[2][((s2 >> 16) & 255)] ^
            boxrowcol[3][((s2 >> 24) & 255)] ^
            boxrowcol[4][((s3 >> 32) & 255)] ^
            boxrowcol[5][((s3 >> 40) & 255)] ^
            boxrowcol[6][((s0 >> 48) & 255)] ^
            boxrowcol[7][((s0 >> 56) & 255)];
    out[2] = rkey[2] ^ boxrowcol[0][s2 & 255] ^
            boxrowcol[1][((s2 >> 8) & 255)] ^
            boxrowcol[2][((s3 >> 16) & 255)] ^
            boxrowcol[3][((s3 >> 24) & 255)] ^
            boxrowcol[4][((s0 >> 32) & 255)] ^
            boxrowcol[5][((s0 >> 40) & 255)] ^
            boxrowcol[6][((s1 >> 48) & 255)] ^
            boxrowcol[7][((s1 >> 56) & 255)];
    out[3] = rkey[3] ^ boxrowcol[0][s3 & 255] ^
            boxrowcol[1][((s3 >> 8) & 255)] ^
            boxrowcol[2][((s0 >> 16) & 255)] ^
            boxrowcol[3][((s0 >> 24) & 255)] ^
            boxrowcol[4][((s1 >> 32) & 255)] ^
            boxrowcol[5][((s1 >> 40) & 255)] ^
            boxrowcol[6][((s2 >> 48) & 255)] ^
            boxrowcol[7][((s2 >> 56) & 255)];
}

__inline static void inv_subrowcol_xor512(const uint64_t *state, uint64_t *out, const uint64_t *rkey,
        uint64_t boxrowcol[8][256])
{
    uint64_t s0 = state[0];
    uint64_t s1 = state[1];
    uint64_t s2 = state[2];
    uint64_t s3 = state[3];
    uint64_t s4 = state[4];
    uint64_t s5 = state[5];
    uint64_t s6 = state[6];
    uint64_t s7 = state[7];
    out[0] = rkey[0] ^ boxrowcol[0][s0 & 255] ^
            boxrowcol[1][((s1 >> 8) & 255)] ^
            boxrowcol[2][((s2 >> 16) & 255)] ^
            boxrowcol[3][((s3 >> 24) & 255)] ^
            boxrowcol[4][((s4 >> 32) & 255)] ^
            boxrowcol[5][((s5 >> 40) & 255)] ^
            boxrowcol[6][((s6 >> 48) & 255)] ^
            boxrowcol[7][((s7 >> 56) & 255)];
    out[1] = rkey[1] ^ boxrowcol[0][s1 & 255] ^
            boxrowcol[1][((s2 >> 8) & 255)] ^
            boxrowcol[2][((s3 >> 16) & 255)] ^
            boxrowcol[3][((s4 >> 24) & 255)] ^
            boxrowcol[4][((s5 >> 32) & 255)] ^
            boxrowcol[5][((s6 >> 40) & 255)] ^
            boxrowcol[6][((s7 >> 48) & 255)] ^
            boxrowcol[7][((s0 >> 56) & 255)];
    out[2] = rkey[2] ^ boxrowcol[0][s2 & 255] ^
            boxrowcol[1][((s3 >> 8) & 255)] ^
            boxrowcol[2][((s4 >> 16) & 255)] ^
            boxrowcol[3][((s5 >> 24) & 255)] ^
            boxrowcol[4][((s6 >> 32) & 255)] ^
            boxrowcol[5][((s7 >> 40) & 255)] ^
            boxrowcol[6][((s0 >> 48) & 255)] ^
            boxrowcol[7][((s1 >> 56) & 255)];
    out[3] = rkey[3] ^ boxrowcol[0][s3 & 255] ^
            boxrowcol[1][((s4 >> 8) & 255)] ^
            boxrowcol[2][((s5 >> 16) & 255)] ^
            boxrowcol[3][((s6 >> 24) & 255)] ^
            boxrowcol[4][((s7 >> 32) & 255)] ^
            boxrowcol[5][((s0 >> 40) & 255)] ^
            boxrowcol[6][((s1 >> 48) & 255)] ^
            boxrowcol[7][((s2 >> 56) & 255)];
    out[4] = rkey[4] ^ boxrowcol[0][s4 & 255] ^
            boxrowcol[1][((s5 >> 8) & 255)] ^
            boxrowcol[2][((s6 >> 16) & 255)] ^
            boxrowcol[3][((s7 >> 24) & 255)] ^
            boxrowcol[4][((s0 >> 32) & 255)] ^
            boxrowcol[5][((s1 >> 40) & 255)] ^
            boxrowcol[6][((s2 >> 48) & 255)] ^
            boxrowcol[7][((s3 >> 56) & 255)];
    out[5] = rkey[5] ^ boxrowcol[0][s5 & 255] ^
            boxrowcol[1][((s6 >> 8) & 255)] ^
            boxrowcol[2][((s7 >> 16) & 255)] ^
            boxrowcol[3][((s0 >> 24) & 255)] ^
            boxrowcol[4][((s1 >> 32) & 255)] ^
            boxrowcol[5][((s2 >> 40) & 255)] ^
            boxrowcol[6][((s3 >> 48) & 255)] ^
            boxrowcol[7][((s4 >> 56) & 255)];
    out[6] = rkey[6] ^ boxrowcol[0][s6 & 255 ] ^
            boxrowcol[1][((s7 >> 8) & 255)] ^
            boxrowcol[2][((s0 >> 16) & 255)] ^
            boxrowcol[3][((s1 >> 24) & 255)] ^
            boxrowcol[4][((s2 >> 32) & 255)] ^
            boxrowcol[5][((s3 >> 40) & 255)] ^
            boxrowcol[6][((s4 >> 48) & 255)] ^
            boxrowcol[7][((s5 >> 56) & 255)];
    out[7] = rkey[7] ^ boxrowcol[0][s7 & 255 ] ^
            boxrowcol[1][((s0 >> 8) & 255)] ^
            boxrowcol[2][((s1 >> 16) & 255)] ^
            boxrowcol[3][((s2 >> 24) & 255)] ^
            boxrowcol[4][((s3 >> 32) & 255)] ^
            boxrowcol[5][((s4 >> 40) & 255)] ^
            boxrowcol[6][((s5 >> 48) & 255)] ^
            boxrowcol[7][((s6 >> 56) & 255)];
}


static __inline void inv_subrowcol_sub(const uint64_t *state, uint64_t *out, const uint64_t *rkey, Dstu7624Ctx *ctx)
{
    size_t block_len = ctx->block_len;

    if (block_len == KALINA_128_BLOCK_LEN) {
        uint64_t s0 = state[0];
        uint64_t s1 = state[1];
        out[0] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s0 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s0 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s0 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s0 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s1 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s1 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s1 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s1 >> 56) & 255)]) << 56) - rkey[0];
        out[1] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s1 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s1 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s1 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s1 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s0 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s0 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s0 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s0 >> 56) & 255)]) << 56) - rkey[1];
    }
    if (block_len == KALINA_256_BLOCK_LEN) {
        uint64_t s0 = state[0];
        uint64_t s1 = state[1];
        uint64_t s2 = state[2];
        uint64_t s3 = state[3];
        out[0] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s0 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s0 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s1 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s1 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s2 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s2 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s3 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s3 >> 56) & 255)]) << 56) - rkey[0];
        out[1] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s1 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s1 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s2 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s2 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s3 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s3 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s0 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s0 >> 56) & 255)]) << 56) - rkey[1];
        out[2] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s2 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s2 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s3 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s3 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s0 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s0 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s1 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s1 >> 56) & 255)]) << 56) - rkey[2];
        out[3] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s3 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s3 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s0 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s0 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s1 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s1 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s2 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s2 >> 56) & 255)]) << 56) - rkey[3];
    }
    if (block_len == KALINA_512_BLOCK_LEN) {
        uint64_t s0 = state[0];
        uint64_t s1 = state[1];
        uint64_t s2 = state[2];
        uint64_t s3 = state[3];
        uint64_t s4 = state[4];
        uint64_t s5 = state[5];
        uint64_t s6 = state[6];
        uint64_t s7 = state[7];
        out[0] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s0 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s1 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s2 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s3 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s4 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s5 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s6 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s7 >> 56) & 255)]) << 56) - rkey[0];
        out[1] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s1 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s2 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s3 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s4 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s5 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s6 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s7 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s0 >> 56) & 255)]) << 56) - rkey[1];
        out[2] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s2 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s3 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s4 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s5 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s6 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s7 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s0 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s1 >> 56) & 255)]) << 56) - rkey[2];
        out[3] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s3 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s4 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s5 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s6 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s7 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s0 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s1 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s2 >> 56) & 255)]) << 56) - rkey[3];
        out[4] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s4 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s5 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s6 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s7 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s0 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s1 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s2 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s3 >> 56) & 255)]) << 56) - rkey[4];
        out[5] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s5 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s6 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s7 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s0 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s1 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s2 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s3 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s4 >> 56) & 255)]) << 56) - rkey[5];
        out[6] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s6 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s7 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s0 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s1 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s2 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s3 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s4 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s5 >> 56) & 255)]) << 56) - rkey[6];
        out[7] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (s7 & 255)]) ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s0 >> 8) & 255)]) << 8 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s1 >> 16) & 255)]) << 16 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s2 >> 24) & 255)]) << 24 ^
                (uint64_t) (ctx->sbox_rev[0 * 256 + ((s3 >> 32) & 255)]) << 32 ^
                (uint64_t) (ctx->sbox_rev[1 * 256 + ((s4 >> 40) & 255)]) << 40 ^
                (uint64_t) (ctx->sbox_rev[2 * 256 + ((s5 >> 48) & 255)]) << 48 ^
                (uint64_t) (ctx->sbox_rev[3 * 256 + ((s6 >> 56) & 255)]) << 56) - rkey[7];
    }
}


static __inline void invert_state(uint64_t *state, Dstu7624Ctx *ctx)
{
    size_t block_len = ctx->block_len;
    uint8_t *sbox = ctx->sbox;

    if (block_len == KALINA_128_BLOCK_LEN) {
        state[0] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[0] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[0] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[0] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[0] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[0] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[0] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[0] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[0] >> 56) & 0xFF)]];
        state[1] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[1] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[1] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[1] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[1] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[1] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[1] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[1] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[1] >> 56) & 0xFF)]];
    }
    if (block_len == KALINA_256_BLOCK_LEN) {
        state[0] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[0] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[0] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[0] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[0] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[0] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[0] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[0] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[0] >> 56) & 0xFF)]];
        state[1] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[1] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[1] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[1] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[1] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[1] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[1] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[1] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[1] >> 56) & 0xFF)]];
        state[2] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[2] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[2] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[2] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[2] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[2] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[2] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[2] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[2] >> 56) & 0xFF)]];
        state[3] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[3] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[3] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[3] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[3] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[3] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[3] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[3] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[3] >> 56) & 0xFF)]];
    }
    if (block_len == KALINA_512_BLOCK_LEN) {
        state[0] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[0] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[0] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[0] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[0] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[0] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[0] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[0] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[0] >> 56) & 0xFF)]];
        state[1] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[1] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[1] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[1] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[1] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[1] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[1] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[1] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[1] >> 56) & 0xFF)]];
        state[2] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[2] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[2] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[2] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[2] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[2] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[2] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[2] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[2] >> 56) & 0xFF)]];
        state[3] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[3] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[3] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[3] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[3] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[3] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[3] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[3] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[3] >> 56) & 0xFF)]];
        state[4] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[4] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[4] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[4] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[4] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[4] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[4] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[4] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[4] >> 56) & 0xFF)]];
        state[5] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[5] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[5] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[5] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[5] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[5] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[5] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[5] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[5] >> 56) & 0xFF)]];
        state[6] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[6] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[6] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[6] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[6] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[6] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[6] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[6] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[6] >> 56) & 0xFF)]];
        state[7] = ctx->p_boxrowcol_rev[0][sbox[0 * 256 + (state[7] & 0xFF)]] ^
                ctx->p_boxrowcol_rev[1][sbox[1 * 256 + ((state[7] >> 8) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[2][sbox[2 * 256 + ((state[7] >> 16) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[3][sbox[3 * 256 + ((state[7] >> 24) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[4][sbox[0 * 256 + ((state[7] >> 32) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[5][sbox[1 * 256 + ((state[7] >> 40) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[6][sbox[2 * 256 + ((state[7] >> 48) & 0xFF)]] ^
                ctx->p_boxrowcol_rev[7][sbox[3 * 256 + ((state[7] >> 56) & 0xFF)]];
    }
}

static void reverse_rkey(uint64_t *rkey, Dstu7624Ctx *ctx)
{
    size_t block_len = ctx->block_len;
    size_t key_len  = ctx->key_len;

    if (block_len == KALINA_128_BLOCK_LEN && key_len == KALINA_128_KEY_LEN) {
        invert_state(&rkey[18], ctx);
        invert_state(&rkey[16], ctx);
        invert_state(&rkey[14], ctx);
        invert_state(&rkey[12], ctx);
        invert_state(&rkey[10], ctx);
        invert_state(&rkey[8], ctx);
        invert_state(&rkey[6], ctx);
        invert_state(&rkey[4], ctx);
        invert_state(&rkey[2], ctx);
    }
    if (block_len == KALINA_128_BLOCK_LEN && key_len == KALINA_256_KEY_LEN) {
        invert_state(&rkey[26], ctx);
        invert_state(&rkey[24], ctx);
        invert_state(&rkey[22], ctx);
        invert_state(&rkey[20], ctx);
        invert_state(&rkey[18], ctx);
        invert_state(&rkey[16], ctx);
        invert_state(&rkey[14], ctx);
        invert_state(&rkey[12], ctx);
        invert_state(&rkey[10], ctx);
        invert_state(&rkey[8], ctx);
        invert_state(&rkey[6], ctx);
        invert_state(&rkey[4], ctx);
        invert_state(&rkey[2], ctx);
    }
    if (block_len == KALINA_256_BLOCK_LEN && key_len == KALINA_256_KEY_LEN) {
        invert_state(&rkey[52], ctx);
        invert_state(&rkey[48], ctx);
        invert_state(&rkey[44], ctx);
        invert_state(&rkey[40], ctx);
        invert_state(&rkey[36], ctx);
        invert_state(&rkey[32], ctx);
        invert_state(&rkey[28], ctx);
        invert_state(&rkey[24], ctx);
        invert_state(&rkey[20], ctx);
        invert_state(&rkey[16], ctx);
        invert_state(&rkey[12], ctx);
        invert_state(&rkey[8], ctx);
        invert_state(&rkey[4], ctx);
    }
    if (block_len == KALINA_256_BLOCK_LEN && key_len == KALINA_512_KEY_LEN) {
        invert_state(&rkey[68], ctx);
        invert_state(&rkey[64], ctx);
        invert_state(&rkey[60], ctx);
        invert_state(&rkey[56], ctx);
        invert_state(&rkey[52], ctx);
        invert_state(&rkey[48], ctx);
        invert_state(&rkey[44], ctx);
        invert_state(&rkey[40], ctx);
        invert_state(&rkey[36], ctx);
        invert_state(&rkey[32], ctx);
        invert_state(&rkey[28], ctx);
        invert_state(&rkey[24], ctx);
        invert_state(&rkey[20], ctx);
        invert_state(&rkey[16], ctx);
        invert_state(&rkey[12], ctx);
        invert_state(&rkey[8], ctx);
        invert_state(&rkey[4], ctx);
    }
    if (block_len == KALINA_512_BLOCK_LEN && key_len == KALINA_512_KEY_LEN) {
        invert_state(&rkey[136], ctx);
        invert_state(&rkey[128], ctx);
        invert_state(&rkey[120], ctx);
        invert_state(&rkey[112], ctx);
        invert_state(&rkey[104], ctx);
        invert_state(&rkey[96], ctx);
        invert_state(&rkey[88], ctx);
        invert_state(&rkey[80], ctx);
        invert_state(&rkey[72], ctx);
        invert_state(&rkey[64], ctx);
        invert_state(&rkey[56], ctx);
        invert_state(&rkey[48], ctx);
        invert_state(&rkey[40], ctx);
        invert_state(&rkey[32], ctx);
        invert_state(&rkey[24], ctx);
        invert_state(&rkey[16], ctx);
        invert_state(&rkey[8], ctx);
    }
}

static __inline void subrowcol128_dec(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[2];
    uint64_t *rkey = ctx->p_rkeys_rev;

    state[0] -= rkey[20];
    state[1] -= rkey[21];

    state[0] = ctx->p_boxrowcol_rev[0][s_blocks[0 * 256 + (uint8_t) state[0]]] ^
            ctx->p_boxrowcol_rev[1][s_blocks[1 * 256 + (uint8_t) (state[0] >> 8)]] ^
            ctx->p_boxrowcol_rev[2][s_blocks[2 * 256 + (uint8_t) (state[0] >> 16)]] ^
            ctx->p_boxrowcol_rev[3][s_blocks[3 * 256 + (uint8_t) (state[0] >> 24)]] ^
            ctx->p_boxrowcol_rev[4][s_blocks[0 * 256 + (uint8_t) (state[0] >> 32)]] ^
            ctx->p_boxrowcol_rev[5][s_blocks[1 * 256 + (uint8_t) (state[0] >> 40)]] ^
            ctx->p_boxrowcol_rev[6][s_blocks[2 * 256 + (uint8_t) (state[0] >> 48)]] ^
            ctx->p_boxrowcol_rev[7][s_blocks[3 * 256 + (uint8_t) (state[0] >> 56)]];
    state[1] = ctx->p_boxrowcol_rev[0][s_blocks[0 * 256 + (uint8_t) state[1]]] ^
            ctx->p_boxrowcol_rev[1][s_blocks[1 * 256 + (uint8_t) (state[1] >> 8)]] ^
            ctx->p_boxrowcol_rev[2][s_blocks[2 * 256 + (uint8_t) (state[1] >> 16)]] ^
            ctx->p_boxrowcol_rev[3][s_blocks[3 * 256 + (uint8_t) (state[1] >> 24)]] ^
            ctx->p_boxrowcol_rev[4][s_blocks[0 * 256 + (uint8_t) (state[1] >> 32)]] ^
            ctx->p_boxrowcol_rev[5][s_blocks[1 * 256 + (uint8_t) (state[1] >> 40)]] ^
            ctx->p_boxrowcol_rev[6][s_blocks[2 * 256 + (uint8_t) (state[1] >> 48)]] ^
            ctx->p_boxrowcol_rev[7][s_blocks[3 * 256 + (uint8_t) (state[1] >> 56)]];

    inv_subrowcol_xor128(state, point, &rkey[18], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(point, state, &rkey[16], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(state, point, &rkey[14], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(point, state, &rkey[12], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(state, point, &rkey[10], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(point, state, &rkey[8], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(state, point, &rkey[6], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(point, state, &rkey[4], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(state, point, &rkey[2], ctx->p_boxrowcol_rev);

    state[0] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (uint8_t) point[0]]) ^
            (uint64_t) (ctx->sbox_rev[1 * 256 + (uint8_t) (point[0] >> 8)]) << 8 ^
            (uint64_t) (ctx->sbox_rev[2 * 256 + (uint8_t) (point[0] >> 16)]) << 16 ^
            (uint64_t) (ctx->sbox_rev[3 * 256 + (uint8_t) (point[0] >> 24)]) << 24 ^
            (uint64_t) (ctx->sbox_rev[0 * 256 + (uint8_t) (point[1] >> 32)]) << 32 ^
            (uint64_t) (ctx->sbox_rev[1 * 256 + (uint8_t) (point[1] >> 40)]) << 40 ^
            (uint64_t) (ctx->sbox_rev[2 * 256 + (uint8_t) (point[1] >> 48)]) << 48 ^
            (uint64_t) (ctx->sbox_rev[3 * 256 + (uint8_t) (point[1] >> 56)]) << 56) -
            rkey[0];
    state[1] = ((uint64_t) (ctx->sbox_rev[0 * 256 + (uint8_t) point[1]]) ^
            (uint64_t) (ctx->sbox_rev[1 * 256 + (uint8_t) (point[1] >> 8)]) << 8 ^
            (uint64_t) (ctx->sbox_rev[2 * 256 + (uint8_t) (point[1] >> 16)]) << 16 ^
            (uint64_t) (ctx->sbox_rev[3 * 256 + (uint8_t) (point[1] >> 24)]) << 24 ^
            (uint64_t) (ctx->sbox_rev[0 * 256 + (uint8_t) (point[0] >> 32)]) << 32 ^
            (uint64_t) (ctx->sbox_rev[1 * 256 + (uint8_t) (point[0] >> 40)]) << 40 ^
            (uint64_t) (ctx->sbox_rev[2 * 256 + (uint8_t) (point[0] >> 48)]) << 48 ^
            (uint64_t) (ctx->sbox_rev[3 * 256 + (uint8_t) (point[0] >> 56)]) << 56) -
            rkey[1];
}

static __inline void subrowcol128_256_dec(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[2];
    uint64_t *rkey = ctx->p_rkeys_rev;

    state[0] -= rkey[28];
    state[1] -= rkey[29];

    invert_state(state, ctx);
    inv_subrowcol_xor128(state, point, &rkey[26], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(point, state, &rkey[24], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(state, point, &rkey[22], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(point, state, &rkey[20], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(state, point, &rkey[18], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(point, state, &rkey[16], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(state, point, &rkey[14], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(point, state, &rkey[12], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(state, point, &rkey[10], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(point, state, &rkey[8], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(state, point, &rkey[6], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(point, state, &rkey[4], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor128(state, point, &rkey[2], ctx->p_boxrowcol_rev);
    inv_subrowcol_sub(point, state, &rkey[0], ctx);
}

static __inline void subrowcol256_dec(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[4];
    uint64_t *rkey = ctx->p_rkeys_rev;

    state[0] -= rkey[56];
    state[1] -= rkey[57];
    state[2] -= rkey[58];
    state[3] -= rkey[59];

    invert_state(state, ctx);
    inv_subrowcol_xor256(state, point, &rkey[52], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[48], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[44], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[40], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[36], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[32], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[28], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[24], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[20], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[16], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[12], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[8], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[4], ctx->p_boxrowcol_rev);
    inv_subrowcol_sub(point, state, &rkey[0], ctx);
}

static __inline void subrowcol256_512_dec(Dstu7624Ctx *ctx, uint64_t *state)
{

    uint64_t point[4];
    uint64_t *rkey = ctx->p_rkeys_rev;

    state[0] -= rkey[72];
    state[1] -= rkey[73];
    state[2] -= rkey[74];
    state[3] -= rkey[75];

    invert_state(state, ctx);
    inv_subrowcol_xor256(state, point, &rkey[68], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[64], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[60], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[56], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[52], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[48], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[44], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[40], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[36], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[32], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[28], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[24], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[20], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[16], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[12], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(point, state, &rkey[8], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor256(state, point, &rkey[4], ctx->p_boxrowcol_rev);
    inv_subrowcol_sub(point, state, &rkey[0], ctx);
}

static __inline void subrowcol512_dec(Dstu7624Ctx *ctx, uint64_t *state)
{
    uint64_t point[8];
    uint64_t *rkey = ctx->p_rkeys_rev;

    state[0] -= rkey[144];
    state[1] -= rkey[145];
    state[2] -= rkey[146];
    state[3] -= rkey[147];
    state[4] -= rkey[148];
    state[5] -= rkey[149];
    state[6] -= rkey[150];
    state[7] -= rkey[151];

    invert_state(state, ctx);
    inv_subrowcol_xor512(state, point, &rkey[136], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(point, state, &rkey[128], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(state, point, &rkey[120], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(point, state, &rkey[112], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(state, point, &rkey[104], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(point, state, &rkey[96], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(state, point, &rkey[88], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(point, state, &rkey[80], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(state, point, &rkey[72], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(point, state, &rkey[64], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(state, point, &rkey[56], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(point, state, &rkey[48], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(state, point, &rkey[40], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(point, state, &rkey[32], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(state, point, &rkey[24], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(point, state, &rkey[16], ctx->p_boxrowcol_rev);
    inv_subrowcol_xor512(state, point, &rkey[8], ctx->p_boxrowcol_rev);
    inv_subrowcol_sub(point, state, &rkey[0], ctx);
}

static int precomputed_rkeys(Dstu7624Ctx *ctx, uint64_t *precompute_keyshifts, uint64_t *p_hrkey)
{
    uint8_t swap[64];
    uint8_t id8[64];
    uint64_t id64[8];
    uint64_t rkey[8];
    uint8_t tmp[64];
    size_t i = 0, j = 0;
    size_t shift;
    size_t key_len;
    size_t wblock_len;
    size_t block_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(precompute_keyshifts != NULL);
    CHECK_PARAM(p_hrkey != NULL);

    block_len = ctx->block_len;
    key_len = ctx->key_len >> 3;
    wblock_len = block_len >> 3;
    memset(id8, 0, block_len);

    /*Вычисляем четные раундовые ключи.*/
    for (i = 0; i <= ctx->rounds >> 1; i++) {
        for (j = 0; j < block_len; j++) {
            shift = (1 << i) >> 8;
            if (shift > 0) {
                j++;
                id8[j] = (uint8_t) (1 << (shift - 1));
            } else {
                id8[j] = (uint8_t) (1 << i);
                j++;
            }
        }

        DO(uint8_to_uint64(id8, block_len, id64, wblock_len));

        memcpy(&ctx->p_rkeys[i * (wblock_len * 2)], p_hrkey, block_len);
        kalina_add(id64, &ctx->p_rkeys[i * (wblock_len * 2)], wblock_len);
        memcpy(rkey, &ctx->p_rkeys[i * (wblock_len * 2)], block_len);
        kalina_add(&precompute_keyshifts[i * key_len], &ctx->p_rkeys[i * (wblock_len * 2)], wblock_len);
        sub_shift_mix_xor(rkey, &ctx->p_rkeys[i * (wblock_len * 2)], ctx);
        sub_shift_mix_add(rkey, &ctx->p_rkeys[i * (wblock_len * 2)], ctx);

        memset(id8, 0, block_len);
    }

    shift = block_len - (block_len / 4 + 3);
    /*Вычисляем нечетные раундовые ключи путем смещения четных*/
    for (i = 0; i < ctx->rounds; i += 2) {
        DO(uint64_to_uint8(&ctx->p_rkeys[(i * wblock_len)], block_len >> 3, swap, block_len));
        for (j = 0; j < block_len; j++) {

            tmp[(j + shift) % block_len] = swap[j];
        }
        DO(uint8_to_uint64(tmp, block_len, &ctx->p_rkeys[(i + 1) * wblock_len], block_len >> 3));
    }

cleanup:

    return ret;
}

static int p_help_round_key(const ByteArray *key, Dstu7624Ctx *ctx, uint64_t *hrkey)
{
    uint64_t *key64 = NULL;
    int ret = RET_OK;
    size_t key64_len = 0;
    size_t block64_len;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(hrkey != NULL);

    DO(ba_to_uint64_with_alloc(key, &key64, &key64_len));
    block64_len = ctx->block_len >> 3;

    if (ctx->block_len == ctx->key_len) {
        kalina_add(key64, hrkey, block64_len);
        sub_shift_mix_xor(key64, hrkey, ctx);
        sub_shift_mix_add(key64, hrkey, ctx);
        ctx->subrowcol(hrkey, ctx);
    } else {
        kalina_add(key64, hrkey, (ctx->block_len >> 3));
        sub_shift_mix_xor((key64 + (ctx->block_len >> 3)), hrkey, ctx);
        sub_shift_mix_add(key64, hrkey, ctx);
        ctx->subrowcol(hrkey, ctx);
    }

cleanup:

    if (key64) {
        memset(key64, 0, key64_len * sizeof(uint64_t));
    }
    free(key64);

    return ret;
}

/*Функция для обчислення сдвига секретного ключа.*/
static int p_key_shift(const uint8_t *key, Dstu7624Ctx *ctx, uint64_t **key_shifts)
{
    uint8_t *key_shift;
    uint8_t *key_shift_ptr = NULL;
    size_t i, j = 0;
    size_t shift;
    size_t shift_key_size;
    size_t key_len;
    size_t block_len;
    int ret = RET_OK;

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key_shifts != NULL);

    block_len = ctx->block_len;
    key_len = ctx->key_len;
    shift_key_size = key_len * ((ctx->rounds >> 1) + 1);

    MALLOC_CHECKED(key_shift, shift_key_size);
    key_shift_ptr = key_shift;
    memset(key_shift, 0, shift_key_size);

    MALLOC_CHECKED(*key_shifts, shift_key_size);

    /*Выбираем режим генерирование вспомогательных раундовых ключей.*/
    if (block_len == key_len) {
        for (i = 0; i <= ctx->rounds >> 1; ++i) {
            for (j = 0; j < key_len; ++j) {
                /*Вычисляем размер сдвига*/
                shift = 56 * i;
                /*Создаем новый массив c необходимым сдвигом.*/
                key_shift[(j + shift) % key_len] = key[j];
            }
            key_shift += key_len;
        }
    } else {
        for (i = 0; i <= ctx->rounds >> 1; ++i) {
            for (j = 0; j < key_len; ++j) {
                if (i % 2 == 0) {
                    shift = 60 * i;
                    key_shift[(j + shift) % key_len] = key[j];
                } else {
                    if (key_len == KALINA_256_KEY_LEN) {
                        shift = 48 - ((i >> 1) << 3);
                    } else {
                        shift = 96 - ((i >> 1) << 3);
                    }
                    key_shift[(j + shift) % key_len] = key[j];
                }
            }
            key_shift += key_len;
        }
    }

    DO(uint8_to_uint64(key_shift_ptr, shift_key_size, *key_shifts, shift_key_size >> 3));

cleanup:

    if (key_shift_ptr) {
        memset(key_shift_ptr, 0, shift_key_size);
    }
    free(key_shift_ptr);

    return ret;
}

static int dstu7624_init(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size)
{
    const uint8_t *key_buf = NULL;
    uint64_t *p_hrkey = NULL;
    uint64_t *p_key_shifts = NULL;
    size_t key_buf_len = 0;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(block_size == KALINA_128_BLOCK_LEN || block_size == KALINA_256_BLOCK_LEN
            || block_size == KALINA_512_BLOCK_LEN);

    key_buf = key->buf;
    key_buf_len = key->len;

    CHECK_PARAM(key_buf_len == KALINA_128_KEY_LEN || key_buf_len == KALINA_256_KEY_LEN
            || key_buf_len == KALINA_512_KEY_LEN);

    MALLOC_CHECKED(p_hrkey, key_buf_len);
    memset(p_hrkey, 0, key_buf_len);

    /*Ініціалізація начальных даних ДСТУ7624 у соответсвии з розміром блока і ключа.*/
    if (key_buf_len == KALINA_128_KEY_LEN && block_size == KALINA_128_BLOCK_LEN) {
        p_hrkey[0] = 0x05; // дані для инициализации раундового ключа.
        ctx->subrowcol = subrowcol128; // Операция быстрого обчислення sbox, srow, mcol.
        ctx->basic_transform =
                basic_transform_128; // Операция базового преобразования для данного режиму.
        ctx->subrowcol_dec =
                subrowcol128_dec; // Операция обратного базового преобразования.
        ctx->rounds =
                10; // кількість раундов для генерирования раундового ключа.
    } else if (key_buf_len == KALINA_256_KEY_LEN && block_size == KALINA_128_BLOCK_LEN) {
        p_hrkey[0] = 0x07;
        ctx->subrowcol = subrowcol128;
        ctx->basic_transform = basic_transform_128_256;
        ctx->subrowcol_dec = subrowcol128_256_dec;
        ctx->rounds = 14;
    } else if (key_buf_len == KALINA_256_KEY_LEN && block_size == KALINA_256_BLOCK_LEN) {
        p_hrkey[0] = 0x09;
        ctx->subrowcol = subrowcol256;
        ctx->basic_transform = basic_transform_256;
        ctx->subrowcol_dec = subrowcol256_dec;
        ctx->rounds = 14;
    } else if (key_buf_len == KALINA_512_KEY_LEN && block_size == KALINA_256_BLOCK_LEN) {
        p_hrkey[0] = 0x0D;
        ctx->subrowcol = subrowcol256;
        ctx->basic_transform = basic_transform_256_512;
        ctx->subrowcol_dec = subrowcol256_512_dec;
        ctx->rounds = 18;
    } else if (key_buf_len == KALINA_512_KEY_LEN && block_size == KALINA_512_BLOCK_LEN) {
        p_hrkey[0] = 0x11;
        ctx->subrowcol = subrowcol512;
        ctx->basic_transform = basic_transform_512;
        ctx->subrowcol_dec = subrowcol512_dec;
        ctx->rounds = 18;
    } else {
        SET_ERROR(RET_INVALID_PARAM);
    }

    ctx->key_len = key_buf_len;
    memset(ctx->state, 0, MAX_BLOCK_LEN);
    ctx->block_len = block_size;

    DO(p_key_shift(key_buf, ctx, &p_key_shifts));
    DO(p_help_round_key(key, ctx, p_hrkey));
    DO(precomputed_rkeys(ctx, p_key_shifts, p_hrkey));

    memcpy(&ctx->p_rkeys_rev[0], &ctx->p_rkeys[0], MAX_BLOCK_LEN * 20);
    reverse_rkey(ctx->p_rkeys_rev, ctx);

cleanup:

    if (p_hrkey) {
        secure_zero(p_hrkey, key_buf_len);
    }
    free(p_hrkey);

    if (p_key_shifts) {
        secure_zero(p_key_shifts, key_buf_len * ((ctx->rounds >> 1) + 1));
    }
    free(p_key_shifts);

    return ret;
}

static __inline void decrypt_basic_transform(Dstu7624Ctx *ctx, const uint8_t *cipher_data, uint8_t *plain_data)
{
    uint64_t block[8];

    uint8_to_uint64(cipher_data, ctx->block_len, block, ctx->block_len >> 3);
    ctx->subrowcol_dec(ctx, block);
    uint64_to_uint8(block, ctx->block_len >> 3, plain_data, ctx->block_len);
}

static uint8_t padding(Dstu7624Ctx *ctx, uint8_t *plain_data, size_t *data_size_byte, uint8_t *padded)
{
    size_t padded_byte;
    size_t block_len;

    block_len = ctx->block_len;

    padded_byte = (block_len - *data_size_byte % block_len);
    if (plain_data != padded) {
        memcpy(padded, plain_data, *data_size_byte);
    }

    if (*data_size_byte % block_len != 0) {
        padded[*data_size_byte] = 0x80;
        memset(&padded[*data_size_byte + 1], 0, padded_byte - 1);
        *data_size_byte = *data_size_byte + padded_byte;

        return 1; //Not error value; 1 if there was some padd el, 0 - if not.
    }
    return 0;
}

static uint8_t unpadding(uint8_t *padded_data, size_t *data_size_byte, uint8_t *plain_data)
{
    size_t i;

    i = *data_size_byte - 1;

    while (padded_data[i] == 0) {
        i--;
    }

    if (i == 0) {
        /*must be an error*/
        return 0;
    }

    if (i == *data_size_byte - 1) {
        return 0;
    }

    *data_size_byte = i + 1;
    if (plain_data != padded_data) {
        memcpy(plain_data, padded_data, *data_size_byte);
    }

    return 1;
}

static int ccm_padd(Dstu7624Ctx *ctx, const ByteArray *auth_data, const ByteArray *plain_data,
        uint8_t **h_out, size_t Nb)
{
    uint8_t *a_data_buf = NULL;
    uint8_t *p_data_buf = NULL;
    uint8_t *h = NULL;
    uint8_t G1[64];
    uint8_t G2[64];
    uint8_t B[64];
    uint64_t B64[8];
    size_t i;
    size_t tmp;
    size_t block_len;
    size_t a_data_len, p_data_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(plain_data != NULL);
    CHECK_PARAM(h_out != NULL);
    CHECK_PARAM(ctx->block_len >= Nb + 1);

    /*Начало виробки імітовставки*/
    tmp = ctx->block_len - Nb - 1;
    block_len = ctx->block_len;

    memset(G1, 0, 64);
    memset(G2, 0, 64);
    memset(B, 0, 64);
    memcpy(G1, ctx->mode.ccm.iv, tmp);
    a_data_len = ba_get_len(auth_data);
    CALLOC_CHECKED(a_data_buf, a_data_len + block_len);
    DO(ba_to_uint8(auth_data, a_data_buf, a_data_len));

    p_data_len = ba_get_len(plain_data);
    CALLOC_CHECKED(p_data_buf, p_data_len + block_len);
    DO(ba_to_uint8(plain_data, p_data_buf, p_data_len));

    //Создание заголовка аутентификации
    G1[tmp] = (uint8_t) p_data_len;

    if (ba_get_len(plain_data) > 0) {
        G1[block_len - 1] = 1 << 7; //0b10000000
    } else {
        G1[block_len - 1] = 0;
    }
    //Код довжини імітовставки. Определен у стандарте.
    switch (ctx->mode.ccm.q) {
    case 8:
        G1[block_len - 1] |= 2 << 4;
        break;
    case 16:
        G1[block_len - 1] |= 3 << 4;
        break;
    case 32:
        G1[block_len - 1] |= 4 << 4;
        break;
    case 48:
        G1[block_len - 1] |= 5 << 4;
        break;
    case 64:
        G1[block_len - 1] |= 6 << 4;
        break;
    default:
        break;
    }
    G1[block_len - 1] |= ((Nb - 1));
    //Конец создания заголовка аутентификации

    G2[0] = (uint8_t) a_data_len;

    MALLOC_CHECKED(h, block_len * 2 + a_data_len);

    tmp = a_data_len % block_len;

    memcpy(h, G1, block_len);
    memcpy(&h[block_len], G2, block_len - tmp);
    memcpy(&h[block_len + block_len - tmp], a_data_buf, a_data_len);

    for (i = 0; i < a_data_len + block_len + (block_len - tmp); i += block_len) {
        kalina_xor(B, &h[i], block_len, B);
        uint8_to_uint64(B, block_len, B64, block_len >> 3);
        ctx->basic_transform(ctx, B64);
        DO(uint64_to_uint8(B64, block_len >> 3, B, block_len));
    }

    padding(ctx, p_data_buf, &p_data_len, p_data_buf);
    for (i = 0; i < p_data_len; i += block_len) {
        kalina_xor(B, &p_data_buf[i], block_len, B);
        uint8_to_uint64(B, block_len, B64, block_len >> 3);
        ctx->basic_transform(ctx, B64);
        DO(uint64_to_uint8(B64, block_len >> 3, B, block_len));
    }
    memcpy(h, B, ctx->mode.ccm.q);

    *h_out = h;
    h = NULL;

    /*Конец виробки імітовставки*/

cleanup:

    free(a_data_buf);
    free(p_data_buf);
    free(h);

    return ret;
}

static void gamma_gen(uint8_t *gamma)
{
    size_t i = 0;

    do {
        gamma[i]++;
    } while (gamma[i++] == 0);
}

static int encrypt_ctr(Dstu7624Ctx *ctx, const ByteArray *src, ByteArray **dst)
{
    uint8_t *gamma = ctx->mode.ctr.gamma;
    uint8_t *feed = ctx->mode.ctr.feed;
    size_t offset = ctx->mode.ctr.used_gamma_len;
    ByteArray *out = NULL;
    int ret = RET_OK;
    size_t data_off = 0;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);

    CHECK_NOT_NULL(out = ba_alloc_by_len(src->len));

    /* Использование оставшейся гаммы. */
    if (offset != 0) {
        while (offset < ctx->block_len && data_off < src->len) {
            out->buf[data_off] = src->buf[data_off] ^ gamma[offset];
            data_off++;
            offset++;
        }

        if (offset == ctx->block_len) {
            gamma_gen(feed);
            crypt_basic_transform(ctx, feed, gamma);
            offset = 0;
        }
    }

    if (data_off < src->len) {
        /* Шифрування блоками по 8 байт. */
        for (; data_off + ctx->block_len <= src->len; data_off += ctx->block_len) {
            kalina_xor(&src->buf[data_off], gamma, ctx->block_len, &out->buf[data_off]);

            gamma_gen(feed);
            crypt_basic_transform(ctx, feed, gamma);
        }
        /* Шифрування последнйого неполного блока. */
        for (; data_off < src->len; data_off++) {
            out->buf[data_off] = src->buf[data_off] ^ gamma[offset];
            offset++;
        }
    }

    ctx->mode.ctr.used_gamma_len = offset;
    *dst = out;

cleanup:

    return ret;
}

static int dstu7624_encrypt_ccm(Dstu7624Ctx *ctx, const ByteArray *auth_data, const ByteArray *plain_data,
        ByteArray **h_ba, ByteArray **cipher_data)
{
    uint8_t *p_data_buf = NULL;
    uint8_t *h = NULL;
    uint8_t *h_tmp = NULL;
    size_t p_data_len;
    size_t block_len;
    size_t q;
    Dstu7624CcmCtx *ccm;
    Dstu7624Ctx *ctr = NULL;
    ByteArray *pdata_buf_part = NULL;
    ByteArray *h_part = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(plain_data != NULL);
    CHECK_PARAM(h_ba != NULL);
    CHECK_PARAM(cipher_data != NULL);

    if (ctx->mode_id != DSTU7624_MODE_CCM) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    ccm = &ctx->mode.ccm;
    DO(ccm_padd(ctx, auth_data, plain_data, &h_tmp, ccm->nb));

    q = ccm->q;
    block_len = ctx->block_len;

    CHECK_NOT_NULL(*h_ba = ba_alloc_from_uint8(h_tmp, q));
    p_data_len = ba_get_len(plain_data);
    MALLOC_CHECKED(p_data_buf, p_data_len + block_len);
    DO(ba_to_uint8(plain_data, p_data_buf, p_data_len));

    MALLOC_CHECKED(h, p_data_len + block_len);

    CHECK_NOT_NULL(ctr = dstu7624_alloc(DSTU7624_SBOX_1));
    DO(dstu7624_init_ctr(ctr, ccm->key, ccm->iv_tmp));
    DO(encrypt_ctr(ctr, plain_data, &pdata_buf_part));
    DO(encrypt_ctr(ctr, *h_ba, &h_part));

    CHECK_NOT_NULL(*cipher_data = ba_join(pdata_buf_part, h_part));

cleanup:

    dstu7624_free(ctr);
    ba_free(h_part);
    ba_free(pdata_buf_part);
    free(p_data_buf);
    free(h);
    free(h_tmp);

    return ret;
}

static int dstu7624_decrypt_ccm(Dstu7624Ctx *ctx, const ByteArray *auth_data, const ByteArray *cipher_data,
        ByteArray *h_ba, ByteArray **plain_data)
{
    uint8_t *p_data_buf = NULL;
    uint8_t *check_h = NULL;
    int ret = RET_OK;
    Dstu7624CcmCtx *ccm;
    Dstu7624Ctx *ctr = NULL;
    ByteArray *p_data_part = NULL;
    size_t part_len;
    ByteArray *ans = NULL;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(cipher_data != NULL);
    CHECK_PARAM(h_ba != NULL);
    CHECK_PARAM(plain_data != NULL);

    if (ctx->mode_id != DSTU7624_MODE_CCM) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    ccm = &ctx->mode.ccm;

    CHECK_NOT_NULL(ctr = dstu7624_alloc(DSTU7624_SBOX_1));
    DO(dstu7624_init_ctr(ctr, ccm->key, ccm->iv_tmp));
    DO(encrypt_ctr(ctr, cipher_data, &p_data_part));

    DO(ba_to_uint8_with_alloc(p_data_part, &p_data_buf, &part_len));
    CHECK_NOT_NULL(ans = ba_alloc_from_uint8(p_data_buf, part_len - ccm->q));
    DO(ccm_padd(ctx, auth_data, ans, &check_h, ctx->mode.ccm.nb));

    if (memcmp(check_h, ba_get_buf(h_ba), ccm->q) != 0) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    *plain_data = ans;
    ans = NULL;

cleanup:

    free(p_data_buf);
    dstu7624_free(ctr);
    ba_free(p_data_part);
    free(check_h);
    ba_free(ans);

    return ret;
}

static int encrypt_ecb(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint64_t *plain_data = NULL;
    size_t block_len_word;
    size_t plain_data_size_word;
    size_t i;
    int ret = RET_OK;
    block_len_word = ctx->block_len >> 3;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    if (in->len % ctx->block_len != 0) {
        SET_ERROR(RET_INVALID_DATA_LEN);
    }

    DO(ba_to_uint64_with_alloc(in, &plain_data, &plain_data_size_word));

    for (i = 0; i < plain_data_size_word; i += block_len_word) {
        ctx->basic_transform(ctx, &plain_data[i]);
    }

    CHECK_NOT_NULL(*out = ba_alloc_from_uint64(plain_data, plain_data_size_word));

cleanup:

    free(plain_data);

    return ret;
}

static int decrypt_ecb(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint64_t *plain_data = NULL;
    size_t block_len_word;
    size_t plain_data_size_word;
    size_t i;
    int ret = RET_OK;
    block_len_word = ctx->block_len >> 3;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    if (in->len % ctx->block_len != 0) {
        SET_ERROR(RET_INVALID_DATA_LEN);
    }

    DO(ba_to_uint64_with_alloc(in, &plain_data, &plain_data_size_word));

    for (i = 0; i < plain_data_size_word; i += block_len_word) {
        ctx->subrowcol_dec(ctx, &plain_data[i]);
    }

    CHECK_NOT_NULL(*out = ba_alloc_from_uint64(plain_data, plain_data_size_word));

cleanup:

    free(plain_data);

    return ret;
}

static int gf2m_mul(Gf2mCtx *ctx, size_t block_len, uint8_t *arg1, uint8_t *arg2, uint8_t *out)
{
    WordArray *wa_arg1 = NULL;
    WordArray *wa_arg2 = NULL;
    WordArray *wa_res = NULL;
    int ret = RET_OK;
    size_t mod_len;
    size_t old_len;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(arg1 != NULL);
    CHECK_PARAM(arg2 != NULL);
    CHECK_PARAM(out != NULL);

    CHECK_NOT_NULL(wa_arg2 = wa_alloc_from_uint8(arg2, block_len));
    CHECK_NOT_NULL(wa_arg1 = wa_alloc_from_uint8(arg1, block_len));

    mod_len = ctx->len;
    old_len = wa_arg1->len;

    CHECK_NOT_NULL(wa_res = wa_alloc(mod_len));

    wa_change_len(wa_arg1, mod_len);
    wa_change_len(wa_arg2, mod_len);

    gf2m_mod_mul(ctx, wa_arg1, wa_arg2, wa_res);

    wa_res->len = old_len;
    DO(wa_to_uint8(wa_res, out, block_len));
    wa_res->len = mod_len;

cleanup:

    wa_free(wa_res);
    wa_free(wa_arg2);
    wa_free(wa_arg1);

    return ret;
}

static int encrypt_xts(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *plain_data = NULL;
    uint8_t two[64] = {0};
    uint8_t gamma[64] = {0};
    size_t plain_size;
    size_t i;
    size_t block_len;
    size_t loop_len;
    size_t padded_len = 0;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    block_len = ctx->block_len;
    two[0] = 2;

    plain_size = ba_get_len(in);

    padded_len = block_len - (plain_size % block_len);
    MALLOC_CHECKED(plain_data, plain_size + padded_len);
    DO(ba_to_uint8(in, plain_data, plain_size));

    crypt_basic_transform(ctx, ctx->mode.xts.iv, gamma);

    if (padded_len == block_len) {
        loop_len = plain_size;
    } else {
        loop_len = plain_size - block_len;
    }

    for (i = 0; i < loop_len; i += block_len) {
        DO(gf2m_mul(ctx->mode.xts.gf2m_ctx, block_len, gamma, two, gamma));
        kalina_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
        crypt_basic_transform(ctx, &plain_data[i], &plain_data[i]);
        kalina_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
    }

    if (padded_len != block_len) {
        //Дополняем последний блок шифротекстом предпоследнего
        i += plain_size % block_len;
        memcpy(&plain_data[i], &plain_data[i - block_len], padded_len);
        i -= plain_size % block_len;

        //Конвертируем а для бе машин.
        DO(gf2m_mul(ctx->mode.xts.gf2m_ctx, block_len, gamma, two, gamma));
        kalina_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
        crypt_basic_transform(ctx, &plain_data[i], &plain_data[i]);
        kalina_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
        //Меняем n-1 блок и nй местами.
        memcpy(gamma, &plain_data[i - block_len], block_len);
        memcpy(&plain_data[i - block_len], &plain_data[i], block_len);
        memcpy(&plain_data[i], gamma, block_len - padded_len);
    }

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(plain_data, plain_size));

cleanup:

    free(plain_data);

    return ret;
}

static int decrypt_xts(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *plain_data = NULL;
    uint8_t gamma[64];
    uint8_t two[64] = {0};
    size_t plain_size;
    size_t block_len;
    size_t i;
    int ret = RET_OK;
    size_t padded_len;
    size_t loop_num;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    two[0] = 2;

    block_len = ctx->block_len;

    memset(gamma, 0, 64);

    plain_size = ba_get_len(in);
    padded_len = block_len - (plain_size % block_len);
    MALLOC_CHECKED(plain_data, plain_size + padded_len);
    DO(ba_to_uint8(in, plain_data, plain_size));

    crypt_basic_transform(ctx, ctx->mode.xts.iv, gamma);

    if (padded_len == block_len) {
        loop_num = plain_size;
    } else {
        loop_num = plain_size < 2 * block_len ? 0 : plain_size - 2 * block_len;
    }

    for (i = 0; i < loop_num; i += block_len) {
        DO(gf2m_mul(ctx->mode.xts.gf2m_ctx, block_len, gamma, two, gamma));
        kalina_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
        decrypt_basic_transform(ctx, &plain_data[i], &plain_data[i]);
        kalina_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
    }

    if (padded_len != block_len) {
        //Если было дополнение, на вход приходят последний и предпоследний блок
        //Так как при дополнении в шифровании меняются местами последний и предпоследний блоки, расшифровуем последний блок, как предпоследний
        DO(gf2m_mul(ctx->mode.xts.gf2m_ctx, block_len, gamma, two, gamma));
        DO(gf2m_mul(ctx->mode.xts.gf2m_ctx, block_len, gamma, two, two));
        kalina_xor(&plain_data[i], two, block_len, &plain_data[i]);
        decrypt_basic_transform(ctx, &plain_data[i], &plain_data[i]);
        kalina_xor(&plain_data[i], two, block_len, &plain_data[i]);

        //В конце предпоследнего блока хранится дополнение к последнему блоку
        i += block_len;
        i += plain_size % block_len;
        //Записываем полученое дополнение и расшифровуем
        memcpy(&plain_data[i], &plain_data[i - block_len], padded_len);
        i -= plain_size % block_len;

        kalina_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
        decrypt_basic_transform(ctx, &plain_data[i], &plain_data[i]);
        kalina_xor(&plain_data[i], gamma, block_len, &plain_data[i]);

        //Меняем n-1 блок и nй местами.
        memcpy(gamma, &plain_data[i - block_len], block_len);
        memcpy(&plain_data[i - block_len], &plain_data[i], block_len);
        memcpy(&plain_data[i], gamma, block_len - padded_len);
    }
    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(plain_data, plain_size));

cleanup:

    free(plain_data);

    return ret;
}

static int encrypt_cbc(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *cipher_data = NULL;
    size_t block_len;
    size_t plain_data_size_byte;
    size_t i;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    block_len = ctx->block_len;

    if (in->len % block_len != 0) {
        SET_ERROR(RET_INVALID_DATA_LEN);
    }

    plain_data_size_byte = in->len;

    CALLOC_CHECKED(cipher_data, (plain_data_size_byte + (block_len - plain_data_size_byte % block_len)));
    memcpy(cipher_data, in->buf, in->len);

    for (i = 0; i < plain_data_size_byte; i += block_len) {
        kalina_xor(&cipher_data[i], ctx->mode.cbc.gamma, block_len, ctx->mode.cbc.gamma);
        crypt_basic_transform(ctx, ctx->mode.cbc.gamma, ctx->mode.cbc.gamma);
        memcpy(&cipher_data[i], ctx->mode.cbc.gamma, block_len);
    }

    CHECK_NOT_NULL(*out = ba_alloc());
    (*out)->buf = cipher_data;
    (*out)->len = plain_data_size_byte;
    cipher_data = NULL;

cleanup:

    free(cipher_data);

    return ret;
}

static int encrypt_cfb(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **dst)
{
    size_t offset = ctx->mode.cfb.used_gamma_len;
    uint8_t *gamma = ctx->mode.cfb.gamma;
    uint8_t *feed = ctx->mode.cfb.feed;
    ByteArray *out = NULL;
    int ret = RET_OK;
    size_t data_off = 0;
    size_t q = ctx->mode.cfb.q;

    CHECK_NOT_NULL(out = ba_alloc_by_len(in->len));

    /* Использование оставшейся гаммы. */
    if (offset != 0) {
        while (offset < q && data_off < in->len) {
            out->buf[data_off] = in->buf[data_off] ^ gamma[offset];
            feed[offset++] = out->buf[data_off++];
        }

        if (offset == ctx->block_len) {
            crypt_basic_transform(ctx, feed, gamma);
            offset = ctx->block_len - q;
        }
    }

    if (data_off < in->len) {
        /* Шифрування блоками по ctx->block_len байт. */
        for (; data_off + q <= in->len; data_off += q) {
            kalina_xor(&in->buf[data_off], &gamma[offset], q, &out->buf[data_off]);

            memcpy(feed, gamma, ctx->block_len);
            memcpy(&feed[offset], &out->buf[data_off], q);

            crypt_basic_transform(ctx, feed, gamma);
        }
        /* Шифрування последнйого неполного блока. */
        for (; data_off < in->len; data_off++) {
            out->buf[data_off] = in->buf[data_off] ^ gamma[ctx->block_len - (in->len - data_off)];
            feed[offset++] = out->buf[data_off];
        }
    }

    ctx->mode.cfb.used_gamma_len = offset;
    *dst = out;

cleanup:

    return ret;
}

static int dstu7624_encrypt_gcm(Dstu7624Ctx *ctx, const ByteArray *plain_data, const ByteArray *auth_data,
        ByteArray **h, ByteArray **cipher_text)
{
    uint8_t *auth_buf = NULL;
    uint8_t *plain_buf = NULL;
    uint64_t gamma[8];
    uint8_t gamma8[64];
    uint64_t gamma_old[8];
    uint64_t H[8];
    uint64_t B[8];
    uint8_t H8[64];
    uint8_t B8[64];
    size_t auth_len;
    size_t plain_len;
    size_t i = 0;
    size_t block_len;
    size_t block_len_word;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(plain_data != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(h != NULL);
    CHECK_PARAM(cipher_text != NULL);

    block_len = ctx->block_len;
    block_len_word = block_len >> 3;

    memset(gamma, 0, 64);
    memset(gamma_old, 0, 64);
    memset(B, 0, 64);
    memset(H, 0, 64);

    auth_len = ba_get_len(auth_data);
    MALLOC_CHECKED(auth_buf, auth_len + block_len);
    plain_len = ba_get_len(plain_data);
    MALLOC_CHECKED(plain_buf, plain_len + block_len);

    memcpy(gamma_old, ctx->mode.gcm.iv, ctx->block_len);
    ctx->basic_transform(ctx, gamma_old);

    DO(ba_to_uint8(auth_data, auth_buf, auth_len));
    DO(ba_to_uint8(plain_data, plain_buf, plain_len));

    /*Шифрування і обеспечение целостности.*/
    for (i = 0; i < plain_len; i += block_len) {
        gamma_old[0]++;
        memcpy(gamma, gamma_old, block_len);
        ctx->basic_transform(ctx, gamma);
        uint64_to_uint8(gamma, block_len_word, gamma8, block_len);
        kalina_xor(&plain_buf[i], gamma8, block_len, &plain_buf[i]);
    }

    CHECK_NOT_NULL(*cipher_text = ba_alloc_from_uint8(plain_buf, plain_len));

    /*Выработка імітовставки.*/
    padding(ctx, plain_buf, &plain_len, plain_buf);
    ctx->basic_transform(ctx, H);
    /*H - у ле формате. Для умножения нам нужно 2 бе формата. auth_buf - бе.*/
    DO(uint64_to_uint8(H, block_len_word, H8, block_len));
    for (i = 0; i < auth_len; i += block_len) {
        kalina_xor(&auth_buf[i], B, block_len, B);
        DO(gf2m_mul(ctx->mode.gcm.gf2m_ctx, block_len, (uint8_t *) B, H8, (uint8_t *) B));
    }

    for (i = 0; i < plain_len; i += block_len) {
        kalina_xor(&plain_buf[i], B, block_len, B);
        DO(gf2m_mul(ctx->mode.gcm.gf2m_ctx, block_len, (uint8_t *) B, H8, (uint8_t *) B));
    }

    memset(H, 0, 64);
    auth_len <<= 3;
    plain_len <<= 3;
    for (i = 0; auth_len != 0; i++) {
        H[0] ^= (auth_len & 255) << (i << 3);
        auth_len >>= 8;
    }
    for (i = 0; plain_len != 0; i++) {
        H[((block_len / 2) >> 3)] ^= (plain_len & 255) << (i << 3);
        plain_len >>= 8;
    }

    DO(uint64_to_uint8(B, block_len_word, B8, block_len));
    kalina_xor(H, B8, block_len, H);
    ctx->basic_transform(ctx, H);
    DO(uint64_to_uint8(H, block_len_word, H8, block_len));
    CHECK_NOT_NULL(*h = ba_alloc_from_uint8(H8, ctx->mode.gcm.q));

cleanup:

    free(plain_buf);
    free(auth_buf);

    return ret;
}

static int dstu7624_decrypt_gcm(Dstu7624Ctx *ctx, const ByteArray *cipher_data, const ByteArray *h_ba,
        const ByteArray *auth_data, ByteArray **out)
{
    uint8_t *auth_buf = NULL;
    uint8_t *plain_buf = NULL;
    uint64_t *h = NULL;
    uint64_t gamma[8];
    uint8_t gamma8[64];
    uint64_t gamma_old[8];
    uint64_t H[8];
    uint8_t H8[64];
    uint64_t B[8];
    uint8_t B8[64];
    size_t auth_len;
    size_t plain_len;
    size_t h_len;
    size_t block_len;
    size_t block_len_word;
    size_t i = 0;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(cipher_data != NULL);
    CHECK_PARAM(h_ba != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(out != NULL);

    block_len = ctx->block_len;
    block_len_word = block_len >> 3;

    memset(gamma, 0, 64);
    memset(gamma_old, 0, 64);
    memset(B, 0, 64);
    memset(H, 0, 64);

    auth_len = ba_get_len(auth_data);
    MALLOC_CHECKED(auth_buf, auth_len + block_len);
    plain_len = ba_get_len(cipher_data);
    MALLOC_CHECKED(plain_buf, plain_len + block_len);

    memcpy(gamma_old, ctx->mode.gcm.iv, ctx->block_len);
    ctx->basic_transform(ctx, gamma_old);

    DO(ba_to_uint8(auth_data, auth_buf, auth_len));
    DO(ba_to_uint8(cipher_data, plain_buf, plain_len));

    /*Выработка імітовставки.*/
    padding(ctx, plain_buf, &plain_len, plain_buf);

    ctx->basic_transform(ctx, H);
    /*H - у ле формате. Для умножения нам нужно 2 бе формата. auth_buf - бе.*/
    uint64_to_uint8(H, block_len_word, H8, block_len);
    for (i = 0; i < auth_len; i += block_len) {
        kalina_xor(&auth_buf[i], B, block_len, B);
        DO(gf2m_mul(ctx->mode.gcm.gf2m_ctx, block_len, (uint8_t *) B, (uint8_t *) H8, (uint8_t *) B));
    }

    for (i = 0; i < plain_len; i += block_len) {
        kalina_xor(&plain_buf[i], B, block_len, B);
        DO(gf2m_mul(ctx->mode.gcm.gf2m_ctx, block_len, (uint8_t *) B, H8, (uint8_t *) B));
    }

    memset(H, 0, 64);

    auth_len <<= 3;
    plain_len <<= 3;
    for (i = 0; auth_len != 0; i++) {
        H[0] ^= (auth_len & 255) << (i << 3);
        auth_len >>= 8;
    }
    for (i = 0; plain_len != 0; i++) {
        H[((block_len / 2) >> 3)] ^= (plain_len & 255) << (i << 3);
        plain_len >>= 8;
    }

    DO(uint64_to_uint8(B, block_len_word, B8, block_len));
    kalina_xor(H, B8, block_len, H);
    ctx->basic_transform(ctx, H);

    DO(ba_to_uint64_with_alloc(h_ba, &h, &h_len));

    if (memcmp(H, h, ctx->mode.gcm.q)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    /*Шифрування і обеспечение целостности.*/
    auth_len = ba_get_len(auth_data);
    plain_len = ba_get_len(cipher_data);

    for (i = 0; i < plain_len; i += ctx->block_len) {
        gamma_old[0]++;
        memcpy(gamma, gamma_old, ctx->block_len);
        ctx->basic_transform(ctx, gamma);
        DO(uint64_to_uint8(gamma, block_len_word, gamma8, block_len));
        kalina_xor(&plain_buf[i], gamma8, block_len, &plain_buf[i]);
    }
    /**/

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(plain_buf, plain_len));

cleanup:

    free(h);
    free(plain_buf);
    free(auth_buf);

    return ret;
}

static int gmac_update(Dstu7624Ctx *ctx, const ByteArray *plain_data)
{
    uint8_t *data_buf = NULL;
    uint8_t *last_block = NULL;
    uint64_t *B = NULL;
    uint64_t *H = NULL;
    uint8_t H8[MAX_BLOCK_LEN];
    uint8_t B8[MAX_BLOCK_LEN];
    size_t data_len;
    size_t block_len;
    size_t tail_len;
    size_t last_block_len;
    size_t i;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(plain_data != NULL);

    B = ctx->mode.gmac.B;
    H = ctx->mode.gmac.H;
    block_len = ctx->block_len;
    last_block = ctx->mode.gmac.last_block;
    last_block_len = ctx->mode.gmac.last_block_len;

    //Приводим данные к u8 типу
    DO(uint64_to_uint8(B, block_len >> 3, B8, block_len));
    DO(uint64_to_uint8(H, block_len >> 3, H8, block_len));

    data_buf = plain_data->buf;
    data_len = plain_data->len;

    ctx->mode.gmac.msg_tot_len += data_len;
    //Если последний блок не пустой:
    if (last_block_len != 0) {
        /*Если длинна последнего блока и данных в сумме меньше размера блока*/
        if (last_block_len + data_len < block_len) {
            //Добавляем в конец последнего блока новые данные
            memcpy(&last_block[last_block_len], data_buf, data_len);
            ctx->mode.gmac.last_block_len += data_len;
            goto cleanup;
        } else {
            //Ксорим последний блок с текущими данными
            kalina_xor(last_block, B8, last_block_len, B8);
            tail_len = block_len - last_block_len;
            //Ксорим первые байты из пришедшего блока, до размера блока.
            kalina_xor(data_buf, &B8[last_block_len], tail_len, &B[last_block_len]);
            data_len -= tail_len;
        }
    } else {

        if (data_len >= block_len) {
            kalina_xor(&data_buf[0], B8, block_len, B8);
        } else {
            memcpy(last_block, data_buf, data_len);
            ctx->mode.gmac.last_block_len = data_len;
            goto cleanup;
        }
    }
    //Высчитываем остаток
    tail_len = (block_len - data_len % block_len) % block_len;

    data_len -= tail_len;
    for (i = 0; i < data_len; i += block_len) {
        DO(gf2m_mul(ctx->mode.gmac.gf2m_ctx, block_len, B8, H8, B8));
        if ((i + block_len) < data_len) {
            kalina_xor(&data_buf[i], B8, block_len, B8);
        }
    }

    if (tail_len != 0) {
        memcpy(last_block, &data_buf[i], tail_len);
        ctx->mode.gmac.last_block_len = tail_len;
    }

    DO(uint8_to_uint64(B8, block_len, B, block_len >> 3));

cleanup:

    return ret;
}

static int gmac_final(Dstu7624Ctx *ctx, ByteArray **mac)
{
    uint8_t *last_block = NULL;
    uint64_t *H;
    uint64_t *B;
    uint8_t B8[MAX_BLOCK_LEN];
    uint8_t H8[MAX_BLOCK_LEN];
    size_t last_block_len;
    size_t block_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(mac != NULL);

    B = ctx->mode.gmac.B;
    H = ctx->mode.gmac.H;
    block_len = ctx->block_len;
    last_block = ctx->mode.gmac.last_block;
    last_block_len = ctx->mode.gmac.last_block_len;

    DO(uint64_to_uint8(B, block_len >> 3, B8, block_len));
    DO(uint64_to_uint8(H, block_len >> 3, H8, block_len));

    // Проверяем, нужно ли достчитывать последний блок.
    if (last_block_len != 0) {
        //Если последний блок не нулевой, дополняем его.
        padding(ctx, last_block, &last_block_len, last_block);

        kalina_xor(&last_block, B8, last_block_len, B8);
        DO(gf2m_mul(ctx->mode.gmac.gf2m_ctx, block_len, B8, H8, B8));
    }
    memset(H, 0, MAX_BLOCK_LEN);

    //Записываем длинну всего сообщения в битах
    H[0] = ctx->mode.gmac.msg_tot_len << 3;

    DO(uint64_to_uint8(H, block_len >> 3, H8, block_len));
    kalina_xor(H8, B8, block_len, H8);
    DO(uint8_to_uint64(H8, block_len, H, block_len >> 3));
    ctx->basic_transform(ctx, H);

    DO(uint64_to_uint8(H, block_len >> 3, H8, block_len));
    CHECK_NOT_NULL(*mac = ba_alloc_from_uint8(H8, ctx->mode.gmac.q));

cleanup:

    return ret;
}

static int encrypt_gmac(Dstu7624Ctx *ctx, const ByteArray *plain_data, ByteArray **out)
{
    uint8_t *data_buf = NULL;
    uint64_t H[8];
    uint8_t H8[64];
    uint64_t B[8];
    uint8_t B8[64];
    size_t data_len;
    size_t i;
    size_t block_len;
    size_t block_len_word;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(plain_data != NULL);
    CHECK_PARAM(out != NULL);

    block_len = ctx->block_len;
    block_len_word = block_len >> 3;
    memset(H, 0, 64);
    memset(B, 0, 64);
    memset(H8, 0, 64);
    memset(B8, 0, 64);
    data_len = ba_get_len(plain_data);
    MALLOC_CHECKED(data_buf, data_len + block_len);
    DO(ba_to_uint8(plain_data, data_buf, data_len));

    padding(ctx, data_buf, &data_len, data_buf);
    ctx->basic_transform(ctx, H);
    DO(uint64_to_uint8(H, block_len_word, H8, block_len));
    for (i = 0; i < data_len; i += block_len) {
        kalina_xor(&data_buf[i], B, block_len, B);
        DO(gf2m_mul(ctx->mode.gmac.gf2m_ctx, block_len, (uint8_t *) B, H8, (uint8_t *) B));
    }

    memset(H, 0, 64);

    H[0] = data_len << 3;
    DO(uint64_to_uint8(B, block_len_word, B8, block_len));
    kalina_xor(H, B8, block_len, H);
    ctx->basic_transform(ctx, H);
    DO(uint64_to_uint8(H, block_len_word, H8, block_len));

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(H8, ctx->mode.gmac.q));

cleanup:

    free(data_buf);

    return ret;
}

static int encrypt_ofb(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *plain_data = NULL;
    uint8_t *gamma = NULL;
    size_t plain_data_size_byte;
    size_t i;
    size_t block_len;
    size_t used_gamma_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    block_len = ctx->block_len;
    plain_data_size_byte = ba_get_len(in);
    CALLOC_CHECKED(plain_data, ((plain_data_size_byte / block_len) + 1) * block_len);
    DO(ba_to_uint8(in, plain_data, plain_data_size_byte));

    gamma = ctx->mode.ofb.gamma;
    used_gamma_len = ctx->mode.ofb.used_gamma_len;
    if (used_gamma_len != 0) {
        //Если размер пришедших данных меньше чем оставшегося хеша, то шифруем только пришедших данные.
        kalina_xor(plain_data, &gamma[used_gamma_len],
                (block_len - used_gamma_len) > plain_data_size_byte ? plain_data_size_byte : (block_len - used_gamma_len),
                plain_data);
    }

    i = used_gamma_len == block_len ? block_len : used_gamma_len;
    for (; i < plain_data_size_byte; i += block_len) {
        crypt_basic_transform(ctx, gamma, gamma);
        kalina_xor(&plain_data[i], gamma, block_len, &plain_data[i]);
    }

    CHECK_NOT_NULL(*out = ba_alloc());
    (*out)->buf = plain_data;
    (*out)->len = plain_data_size_byte;
    plain_data = NULL;

    ctx->mode.ofb.used_gamma_len = (ctx->mode.ofb.used_gamma_len + plain_data_size_byte) % ctx->block_len;

cleanup:

    free(plain_data);

    return ret;
}

static int encrypt_kw(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *cipher_data = NULL;
    uint8_t *b = NULL;
    uint8_t *shift = NULL;
    uint8_t B[MAX_BLOCK_LEN / 2];
    uint8_t swap[MAX_BLOCK_LEN];
    size_t plain_data_size_bit;
    size_t i;
    size_t block_size_kw_byte;
    size_t plain_data_size_byte;
    size_t b_last_el;
    size_t b_el_count;
    size_t r;
    size_t n;
    size_t v;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    block_size_kw_byte = ctx->block_len >> 1;
    plain_data_size_byte = ba_get_len(in);
    MALLOC_CHECKED(cipher_data, plain_data_size_byte + (ctx->block_len << 2));
    memset(cipher_data, 0, plain_data_size_byte + (ctx->block_len << 2));
    DO(ba_to_uint8(in, cipher_data, plain_data_size_byte));

    i = 0;
    if (plain_data_size_byte % ctx->block_len != 0) {
        plain_data_size_bit = plain_data_size_byte << 3;

        while (plain_data_size_bit != 0) {
            cipher_data[plain_data_size_byte + i] = (plain_data_size_bit & 255);
            i++;
            plain_data_size_bit >>= 8;
        }

        plain_data_size_byte += block_size_kw_byte;
        padding(ctx, cipher_data, &plain_data_size_byte, cipher_data);
    }

    r = plain_data_size_byte / ctx->block_len;
    n = 2 * (r + 1);
    v = (n - 1) * 6;

    plain_data_size_byte += ctx->block_len;

    b_el_count = ((n - 1) * (block_size_kw_byte));
    b_last_el = (n - 2) * (block_size_kw_byte);

    MALLOC_CHECKED(b, n * block_size_kw_byte);
    MALLOC_CHECKED(shift, n * block_size_kw_byte);

    memcpy(B, cipher_data, block_size_kw_byte);
    memcpy(b, cipher_data + block_size_kw_byte, b_el_count);

    for (i = 1; i <= v; i++) {
        memcpy(swap, B, block_size_kw_byte);
        memcpy(swap + (block_size_kw_byte), b, block_size_kw_byte);
        crypt_basic_transform(ctx, swap, swap);
        swap[block_size_kw_byte] ^= i;
        memcpy(B, swap + (block_size_kw_byte), block_size_kw_byte);
        memcpy(shift, b + (block_size_kw_byte), b_el_count);
        memcpy(b, shift, b_el_count - block_size_kw_byte);
        memcpy(b + b_last_el, swap, block_size_kw_byte);
    }

    memcpy(cipher_data, B, block_size_kw_byte);
    memcpy(cipher_data + block_size_kw_byte, b, b_el_count);

    CHECK_NOT_NULL(*out = ba_alloc());
    (*out)->buf = cipher_data;
    (*out)->len = b_el_count + block_size_kw_byte;
    cipher_data = NULL;

cleanup:

    free(shift);
    free(b);
    free(cipher_data);

    return ret;
}

static int decrypt_ctr(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    return encrypt_ctr(ctx, in, out);
}

static int decrypt_cfb(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **dst)
{
    size_t offset = ctx->mode.cfb.used_gamma_len;
    uint8_t *gamma = ctx->mode.cfb.gamma;
    uint8_t *feed = ctx->mode.cfb.feed;
    ByteArray *out = NULL;
    int ret = RET_OK;
    size_t data_off = 0;
    size_t q = ctx->mode.cfb.q;

    CHECK_NOT_NULL(out = ba_alloc_by_len(in->len));

    /* Использование оставшейся гаммы. */
    if (offset != 0) {
        while (offset < q && data_off < in->len) {
            out->buf[data_off] = in->buf[data_off] ^ gamma[offset];
            feed[offset++] = in->buf[data_off++];
        }

        if (offset == ctx->block_len) {
            crypt_basic_transform(ctx, feed, gamma);
            offset = ctx->block_len - q;
        }
    }

    if (data_off < in->len) {
        /* Шифрування блоками по ctx->block_len байт. */
        for (; data_off + q <= in->len; data_off += q) {
            kalina_xor(&in->buf[data_off], &gamma[offset], q, &out->buf[data_off]);

            memcpy(feed, gamma, ctx->block_len);
            memcpy(&feed[offset], &in->buf[data_off], q);

            crypt_basic_transform(ctx, feed, gamma);
        }
        /* Шифрування последнйого неполного блока. */
        for (; data_off < in->len; data_off++) {
            out->buf[data_off] = in->buf[data_off] ^ gamma[ctx->block_len - (in->len - data_off)];
            feed[offset++] = in->buf[data_off];
        }
    }

    ctx->mode.cfb.used_gamma_len = offset;
    *dst = out;

cleanup:

    return ret;
}

static int decrypt_kw(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *cipher_data = NULL;
    uint8_t *b = NULL;
    uint8_t swap[MAX_BLOCK_LEN];
    uint8_t *shift = NULL;
    uint8_t B[MAX_BLOCK_LEN >> 1];
    size_t i;
    size_t cipher_data_size_byte;
    size_t block_size_kw_byte;
    size_t b_last_el;
    size_t b_el_count;
    size_t r;
    size_t n;
    size_t v;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    DO(ba_to_uint8_with_alloc(in, &cipher_data, &cipher_data_size_byte));

    block_size_kw_byte = ctx->block_len >> 1;

    r = (cipher_data_size_byte / ctx->block_len) - 1;
    n = 2 * (r + 1);
    v = (n - 1) * 6;

    memcpy(B, cipher_data, block_size_kw_byte);

    MALLOC_CHECKED(b, cipher_data_size_byte);

    b_el_count = ((n - 1) * block_size_kw_byte);

    memcpy(b, cipher_data + block_size_kw_byte, b_el_count);

    b_last_el = (n - 2) * block_size_kw_byte;

    MALLOC_CHECKED(shift, cipher_data_size_byte);
    for (i = v; i >= 1; i--) {
        memcpy(swap, b + b_last_el, block_size_kw_byte);
        B[0] ^= i;
        memcpy(swap + block_size_kw_byte, B, block_size_kw_byte);
        decrypt_basic_transform(ctx, swap, swap);
        memcpy(B, swap, block_size_kw_byte);
        memcpy(shift, b, cipher_data_size_byte - block_size_kw_byte);
        memcpy(b + block_size_kw_byte, shift, b_el_count);
        memcpy(b, swap + block_size_kw_byte, block_size_kw_byte);
    }

    memcpy(cipher_data, B, block_size_kw_byte);
    memcpy(cipher_data + block_size_kw_byte, b, b_el_count);

    unpadding(cipher_data, &cipher_data_size_byte, cipher_data);

    if (cipher_data_size_byte % ctx->block_len != 0) {
        cipher_data_size_byte -= block_size_kw_byte + 1;
    }

    CHECK_NOT_NULL(*out = ba_alloc());
    (*out)->buf = cipher_data;
    (*out)->len = cipher_data_size_byte;
    cipher_data = NULL;

cleanup:

    free(cipher_data);
    free(b);
    free(shift);

    return ret;
}

static int decrypt_cbc(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    uint8_t *cipher_data = NULL;
    uint8_t *plain_data = NULL;
    size_t block_len;
    size_t data_len;
    size_t i;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    block_len = ctx->block_len;

    cipher_data = in->buf;
    data_len = in->len;
    MALLOC_CHECKED(plain_data, data_len);

    for (i = 0; i < data_len; i += block_len) {
        decrypt_basic_transform(ctx, &cipher_data[i], &plain_data[i]);
        kalina_xor(ctx->mode.cbc.gamma, &plain_data[i], block_len, &plain_data[i]);
        memcpy(ctx->mode.cbc.gamma, &cipher_data[i], ctx->block_len);
    }

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(plain_data, data_len));

cleanup:

    free(plain_data);

    return ret;
}

int dstu7624_init_ecb(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);

    DO(dstu7624_init(ctx, key, block_size));

    ctx->mode_id = DSTU7624_MODE_ECB;

cleanup:

    return ret;
}

int dstu7624_init_cbc(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);

    DO(dstu7624_init(ctx, key, iv->len));

    memcpy(ctx->mode.cbc.gamma, iv->buf, ctx->block_len);

    ctx->mode_id = DSTU7624_MODE_CBC;

cleanup:

    return ret;
}

int dstu7624_init_kw(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);

    DO(dstu7624_init(ctx, key, block_size));

    ctx->mode_id = DSTU7624_MODE_KW;

cleanup:

    return ret;
}

int dstu7624_init_cfb(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv, const size_t q)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);
    CHECK_PARAM(q != 0 && q <= iv->len);
    CHECK_PARAM(q == 1 || q == 8 || q == 16 || q == 32 || q == 64);

    DO(dstu7624_init(ctx, key, ba_get_len(iv)));
    DO(ba_to_uint8(iv, ctx->mode.cfb.gamma, ctx->block_len));

    ctx->mode.cfb.q = q;

    DO(ba_to_uint8(iv, ctx->mode.cfb.feed, ctx->block_len));
    ctx->mode.cfb.used_gamma_len = ctx->block_len;

    ctx->mode_id = DSTU7624_MODE_CFB;

cleanup:

    return ret;
}

int dstu7624_init_ofb(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);

    DO(dstu7624_init(ctx, key, ba_get_len(iv)));

    DO(ba_to_uint8(iv, ctx->mode.ofb.gamma, ctx->block_len));
    ctx->mode.ofb.used_gamma_len = 0;
    ctx->mode_id = DSTU7624_MODE_OFB;

cleanup:

    return ret;
}

int dstu7624_init_gmac(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size, const size_t q)
{
    int ret = RET_OK;
    int f[5] = {0};

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(block_size == 16 || block_size == 32 || block_size == 64);
    CHECK_PARAM( (8 <= q) && (q <= block_size) );

    DO(dstu7624_init(ctx, key, block_size));

    ctx->mode.gmac.q = q;

    switch (block_size) {
    case 16:
        f[0] = 128;
        f[1] = 7;
        f[2] = 2;
        f[3] = 1;
        f[4] = 0;
        break;
    case 32:
        f[0] = 256;
        f[1] = 10;
        f[2] = 5;
        f[3] = 2;
        f[4] = 0;
        break;
    case 64:
        f[0] = 512;
        f[1] = 8;
        f[2] = 5;
        f[3] = 2;
        f[4] = 0;
        break;
    default:
        break;
    }

    CHECK_NOT_NULL(ctx->mode.gmac.gf2m_ctx = gf2m_alloc(f, 5));
    memset(ctx->mode.gmac.B, 0, MAX_BLOCK_LEN);
    memset(ctx->mode.gmac.last_block, 0, MAX_BLOCK_LEN);
    memset(ctx->mode.gmac.H, 0, MAX_BLOCK_LEN);
    ctx->basic_transform(ctx, ctx->mode.gmac.H);
    ctx->mode.gmac.last_block_len = 0;

    ctx->mode_id = DSTU7624_MODE_GMAC;

cleanup:

    return ret;
}

int dstu7624_init_cmac(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size, const size_t q)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(q > 0 && q <= block_size);

    DO(dstu7624_init(ctx, key, block_size));

    ctx->mode.cmac.q = q;
    ctx->mode.cmac.lblock_len = 0;
    ctx->mode_id = DSTU7624_MODE_CMAC;

cleanup:

    return ret;
}

int dstu7624_init_xts(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv)
{
    int f[5] = {0};
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);

    DO(dstu7624_init(ctx, key, ba_get_len(iv)));
    DO(ba_to_uint8(iv, ctx->mode.xts.iv, ctx->block_len));

    switch (ctx->block_len) {
    case 16:
        f[0] = 128;
        f[1] = 7;
        f[2] = 2;
        f[3] = 1;
        f[4] = 0;
        break;
    case 32:
        f[0] = 256;
        f[1] = 10;
        f[2] = 5;
        f[3] = 2;
        f[4] = 0;
        break;
    case 64:
        f[0] = 512;
        f[1] = 8;
        f[2] = 5;
        f[3] = 2;
        f[4] = 0;
        break;
    default:
        break;
    }

    CHECK_NOT_NULL(ctx->mode.xts.gf2m_ctx = gf2m_alloc(f, 5));

    ctx->mode_id = DSTU7624_MODE_XTS;

cleanup:

    return ret;
}

int dstu7624_init_ccm(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv, const size_t q, uint64_t n_max)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);
    CHECK_PARAM(q > 0);
    CHECK_PARAM(n_max >= 8);

    DO(dstu7624_init(ctx, key, ba_get_len(iv)));

    CHECK_PARAM(q <= ctx->block_len);

    ctx->mode.ccm.key = key;

    DO(ba_to_uint8(iv, ctx->mode.ccm.iv, ctx->block_len));
    ctx->mode.ccm.iv_tmp = iv;
    ctx->mode.ccm.q = q;
    ctx->mode.ccm.nb = (size_t) (((n_max - 3) >> 3) + 1);

    ctx->mode_id = DSTU7624_MODE_CCM;

cleanup:

    return ret;
}

int dstu7624_init_gcm(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv, const size_t q)
{
    int f[5] = {0};
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);
    CHECK_PARAM( (8 <= q) && (q <= iv->len) );

    DO(dstu7624_init(ctx, key, ba_get_len(iv)));

    DO(ba_to_uint64(iv, ctx->mode.gcm.iv, ctx->block_len >> 3));

    ctx->mode.gcm.q = q;

    switch (ctx->block_len) {
    case 16:
        f[0] = 128;
        f[1] = 7;
        f[2] = 2;
        f[3] = 1;
        f[4] = 0;
        break;
    case 32:
        f[0] = 256;
        f[1] = 10;
        f[2] = 5;
        f[3] = 2;
        f[4] = 0;
        break;
    case 64:
        f[0] = 512;
        f[1] = 8;
        f[2] = 5;
        f[3] = 2;
        f[4] = 0;
        break;
    default:
        break;
    }

    CHECK_NOT_NULL(ctx->mode.gcm.gf2m_ctx = gf2m_alloc(f, 5));

    ctx->mode_id = DSTU7624_MODE_GCM;

cleanup:

    return ret;
}

static int cmac_update(Dstu7624Ctx *ctx, const ByteArray *in)
{
    uint8_t *shifted_data = NULL;
    uint8_t *plain_data = NULL;
    uint8_t cipher_data[64];
    size_t plain_data_len;
    size_t i, j;
    size_t block_len;
    Dstu7624CmacCtx *cmac = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);

    if (ctx->mode_id != DSTU7624_MODE_CMAC) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    block_len = ctx->block_len;
    cmac = &ctx->mode.cmac;

    /*State in be format -> cipher data in be.*/
    DO(uint64_to_uint8(ctx->state, block_len >> 3, cipher_data, block_len));

    plain_data = in->buf;
    plain_data_len = in->len;

    //Если длинна блока и входных данных меньше размера блока, то записываем данные в последний блок и выходим.
    if (cmac->lblock_len + plain_data_len <= block_len) {
        memcpy(&cmac->last_block[cmac->lblock_len], plain_data, plain_data_len);
        cmac->lblock_len += plain_data_len;
        goto cleanup;
    }
    //Ищем преобразование от последнего блока и остальных данных
    memcpy(&cmac->last_block[cmac->lblock_len], plain_data, block_len - cmac->lblock_len);
    kalina_xor(cmac->last_block, cipher_data, block_len, cipher_data);
    crypt_basic_transform(ctx, cipher_data, cipher_data);
    shifted_data = plain_data + (block_len - cmac->lblock_len);
    plain_data_len -= (block_len - cmac->lblock_len);

    for (i = 0, j = block_len; j < plain_data_len; i += block_len, j += block_len) {
        kalina_xor(&shifted_data[i], cipher_data, block_len, cipher_data);
        crypt_basic_transform(ctx, cipher_data, cipher_data);
    }

    cmac->lblock_len = plain_data_len - i;
    if (cmac->lblock_len != 0) {
        memcpy(cmac->last_block, shifted_data + i, cmac->lblock_len);
    }

    DO(uint8_to_uint64(cipher_data, block_len, ctx->state, block_len >> 3));

cleanup:

    return ret;
}

static int cmac_final(Dstu7624Ctx *ctx, ByteArray **out)
{
    uint8_t cipher_data[64];
    uint8_t rkey[64];
    size_t block_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(out != NULL);

    if (ctx->mode_id != DSTU7624_MODE_CMAC) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    block_len = ctx->block_len;
    DO(uint64_to_uint8(ctx->state, block_len >> 3, cipher_data, block_len));
    memset(rkey, 0, 64);

    rkey[0] = padding(ctx, ctx->mode.cmac.last_block, &ctx->mode.cmac.lblock_len, ctx->mode.cmac.last_block);
    crypt_basic_transform(ctx, rkey, rkey);

    kalina_xor(ctx->mode.cmac.last_block, cipher_data, block_len, cipher_data);

    kalina_xor(rkey, cipher_data, block_len, cipher_data);

    crypt_basic_transform(ctx, cipher_data, cipher_data);

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(cipher_data, ctx->mode.cmac.q));

cleanup:

    return ret;
}

int dstu7624_encrypt(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    if (ctx->mode_id == DSTU7624_MODE_CCM || ctx->mode_id == DSTU7624_MODE_CMAC) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    switch (ctx->mode_id) {
    case DSTU7624_MODE_ECB:
        DO(encrypt_ecb(ctx, in, out));
        break;
    case DSTU7624_MODE_CTR:
        DO(encrypt_ctr(ctx, in, out));
        break;
    case DSTU7624_MODE_CBC:
        DO(encrypt_cbc(ctx, in, out));
        break;
    case DSTU7624_MODE_CFB:
        DO(encrypt_cfb(ctx, in, out));
        break;
    case DSTU7624_MODE_OFB:
        DO(encrypt_ofb(ctx, in, out));
        break;
    case DSTU7624_MODE_XTS:
        DO(encrypt_xts(ctx, in, out));
        break;
    case DSTU7624_MODE_KW:
        DO(encrypt_kw(ctx, in, out));
        break;
    case DSTU7624_MODE_GMAC:
        DO(encrypt_gmac(ctx, in, out));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

int dstu7624_decrypt(Dstu7624Ctx *ctx, const ByteArray *in, ByteArray **out)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    switch (ctx->mode_id) {
    case DSTU7624_MODE_ECB:
        DO(decrypt_ecb(ctx, in, out));
        break;
    case DSTU7624_MODE_CTR:
        DO(decrypt_ctr(ctx, in, out));
        break;
    case DSTU7624_MODE_CBC:
        DO(decrypt_cbc(ctx, in, out));
        break;
    case DSTU7624_MODE_CFB:
        DO(decrypt_cfb(ctx, in, out));
        break;
    case DSTU7624_MODE_OFB:
        DO(encrypt_ofb(ctx, in, out));
        break;
    case DSTU7624_MODE_XTS:
        DO(decrypt_xts(ctx, in, out));
        break;
    case DSTU7624_MODE_KW:
        DO(decrypt_kw(ctx, in, out));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

int dstu7624_init_ctr(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv)
{
    size_t block_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(iv != NULL);

    block_len = ba_get_len(iv);
    DO(dstu7624_init(ctx, key, block_len));

    block_len = ctx->block_len;

    DO(ba_to_uint8(iv, ctx->mode.ctr.gamma, block_len));
    ctx->mode.ctr.used_gamma_len = 0;
    crypt_basic_transform(ctx, ctx->mode.ctr.gamma, ctx->mode.ctr.gamma);
    ctx->mode_id = DSTU7624_MODE_CTR;
    memcpy(ctx->mode.ctr.feed, ctx->mode.ctr.gamma, block_len);
    ctx->mode.ctr.used_gamma_len  = block_len;

cleanup:

    return ret;
}

int dstu7624_update_mac(Dstu7624Ctx *ctx, const ByteArray *data)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);

    switch (ctx->mode_id) {
    case DSTU7624_MODE_GMAC:
        DO(gmac_update(ctx, data));
        break;
    case DSTU7624_MODE_CMAC:
        DO(cmac_update(ctx, data));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

int dstu7624_final_mac(Dstu7624Ctx *ctx, ByteArray **mac)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(mac != NULL);

    switch (ctx->mode_id) {
    case DSTU7624_MODE_GMAC:
        DO(gmac_final(ctx, mac));
        break;
    case DSTU7624_MODE_CMAC:
        DO(cmac_final(ctx, mac));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

int dstu7624_encrypt_mac(Dstu7624Ctx *ctx, const ByteArray *auth_data, const ByteArray *data, ByteArray **mac,
        ByteArray **encrypted_data)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(mac != NULL);
    CHECK_PARAM(encrypted_data != NULL);

    switch (ctx->mode_id) {
    case DSTU7624_MODE_GCM:
        DO(dstu7624_encrypt_gcm(ctx, data, auth_data, mac, encrypted_data));
        break;
    case DSTU7624_MODE_CCM:
        DO(dstu7624_encrypt_ccm(ctx, auth_data, data, mac, encrypted_data));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

int dstu7624_decrypt_mac(Dstu7624Ctx *ctx, const ByteArray *auth_data, const ByteArray *encrypted_data, ByteArray *mac,
        ByteArray **data)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(auth_data != NULL);
    CHECK_PARAM(encrypted_data != NULL);
    CHECK_PARAM(mac != NULL);
    CHECK_PARAM(data != NULL);

    switch (ctx->mode_id) {
    case DSTU7624_MODE_GCM:
        DO(dstu7624_decrypt_gcm(ctx, encrypted_data, mac, auth_data, data));
        break;
    case DSTU7624_MODE_CCM:
        DO(dstu7624_decrypt_ccm(ctx, auth_data, encrypted_data, mac, data));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}
