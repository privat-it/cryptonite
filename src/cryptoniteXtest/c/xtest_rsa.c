/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "openssl/rsa.h"
#include "openssl/pem.h"

#include "xtest.h"
#include "rsa.h"
#include "base64_utils_internal.h"

typedef enum {
    CIPHER_NO_PADDING = 0,
    CIPHER_OAEP,
    CIPHER_PKCS1,
    CIPHER_PKCS1_5,
    SIGN_NO_PADDING,
    SIGN_RSASSA_PSS
} RsaCipherType;

typedef struct {
    PrngCtx *prng;
    size_t h_len;
    void *hash_ctx;
    size_t hash_type;
    RsaCipherType type;
    ByteArray *salt;
    ByteArray *msg_to_check;
    bool is_inited;
    ByteArray *e;
    ByteArray *n;
    ByteArray *d;
    ByteArray *p;
    ByteArray *q;
    ByteArray *dP;
    ByteArray *dQ;
    ByteArray *qInv;
} RsaXtestCtx;

static ByteArray *oct_str_to_ba(uint8_t *str, size_t *str_size)
{
    uint8_t *str_temp = NULL;
    ByteArray *ba = NULL;
    int str_len = 1;
    size_t curr_pos = 1;
    size_t coef = 0;
    int i, j;

    i = str[1] - 0x80;
    if (i <= 0) {
        str_len = str[curr_pos];
        curr_pos++;
    } else if (i == 1) {
        curr_pos++;
        str_len = str[curr_pos];
        curr_pos++;
    } else if (i == 2) {
        curr_pos++;
        str_len = str[curr_pos] * 0xFF + str[curr_pos + 1];
        coef = str[curr_pos];
        curr_pos++; //Последний октет длины
        curr_pos++; //Первый числовой октет
    }

    str_temp = malloc(str_len);
    j = 0;
    for (i = str_len - 1; i >= 0; i--, j++) {
        str_temp[j] = str[curr_pos + i];
    }
    j--;
    if (str_temp[j] == 0) {
        str_len--;
        if (str_len == 0) {
            str_len++;
        } else {
            coef++;
        }
    }
    *str_size = str_len;
    ba = ba_alloc_from_uint8(str_temp, *str_size);
    *str_size += curr_pos + coef;

    free(str_temp);

    return ba;
}

static int rsa_init_with_private_key(RsaXtestCtx *ctx, uint8_t *rsa_key)
{
    ByteArray *version = NULL;
    size_t str_size;
    size_t cur_len;
    int count_len;
    int check = RET_OK;

    if (rsa_key[0] != 0x30) {
        check = RET_INVALID_PRIVATE_KEY;
        goto cleanup;
    }

    count_len = rsa_key[1] - 0x80;
    if (count_len < 0) {
        check = RET_INVALID_PRIVATE_KEY;
        goto cleanup;
    }

    cur_len = 2 + count_len;
    if (rsa_key[cur_len] != 0x02) {
        check = RET_INVALID_PRIVATE_KEY;
        goto cleanup;
    }
    version = oct_str_to_ba(&rsa_key[cur_len], &str_size);
    cur_len += str_size;
    if (version == NULL) {
        check = RET_INVALID_PRIVATE_KEY;
        goto cleanup;
    }
    ctx->n = oct_str_to_ba(&rsa_key[cur_len], &str_size);
    cur_len += str_size;
    if (ctx->n == NULL) {
        check = RET_INVALID_PRIVATE_KEY;
        goto cleanup;
    }
    ctx->e = oct_str_to_ba(&rsa_key[cur_len], &str_size);
    cur_len += str_size;
    if (ctx->e == NULL) {
        check = RET_INVALID_PRIVATE_KEY;
        goto cleanup;
    }

    ctx->d = oct_str_to_ba(&rsa_key[cur_len], &str_size);
    cur_len += str_size;
    if (ctx->d == NULL) {
        check = RET_INVALID_PRIVATE_KEY;
        goto cleanup;
    }
    ctx->p = oct_str_to_ba(&rsa_key[cur_len], &str_size);
    cur_len += str_size;
    if (ctx->p == NULL) {
        check = RET_INVALID_PRIVATE_KEY;
        goto cleanup;
    }
    ctx->q = oct_str_to_ba(&rsa_key[cur_len], &str_size);
    cur_len += str_size;
    if (ctx->q == NULL) {
        check = RET_INVALID_PRIVATE_KEY;
        goto cleanup;
    }
    ctx->dP = oct_str_to_ba(&rsa_key[cur_len], &str_size);
    cur_len += str_size;
    if (ctx->dP == NULL) {
        check = RET_INVALID_PRIVATE_KEY;
        goto cleanup;
    }
    ctx->dQ = oct_str_to_ba(&rsa_key[cur_len], &str_size);
    cur_len += str_size;
    if (ctx->dQ == NULL) {
        check = RET_INVALID_PRIVATE_KEY;
        goto cleanup;
    }
    ctx->qInv = oct_str_to_ba(&rsa_key[cur_len], &str_size);
    cur_len += str_size;
    if (ctx->qInv == NULL) {
        check = RET_INVALID_PRIVATE_KEY;
        goto cleanup;
    }

cleanup:

    ba_free(version);

    return check;
}

static int rsa_init_private_key_from_b64(RsaXtestCtx *ctx, uint8_t *hex)
{
    char *buf = NULL;
    uint8_t *dec_buf = NULL;
    size_t buf_size;
    size_t buf_out_size;
    int check = RET_OK;
    size_t i = 0, j = 0;

    buf_size = 10000;
    buf = malloc(buf_size);
    memset(buf, 0, buf_size);
    if (buf == NULL) {
        check = RET_MEMORY_ALLOC_ERROR;
        goto cleanup;
    }
    while ((buf[i] = hex[j]) != '\0') {
        if (buf[i] == '-') {
            do {
                j++;
            } while (hex[j] != '\n');
            continue;
        }
        if (buf[i] == '\n' || buf[i] == ' ') {
            j++;
            continue;
        }
        i++;
        j++;
        if ((i + 1) == buf_size) {
            buf_size += buf_size;
            buf = realloc(buf, buf_size);
        }
    }
    dec_buf = base64_decode(buf, i, &buf_out_size);
    check = rsa_init_with_private_key(ctx, dec_buf);
    if (check != RET_OK) {
        goto cleanup;
    }


cleanup:

    free(dec_buf);
    free(buf);

    return check;
}

static void rsa_atest_ossl_oaep(TableBuilder *ctx_tb)
{
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());
    RsaXtestCtx* cryptonite_ctx = NULL;
    RsaCtx *ctx = NULL;
    ByteArray *enc_os = NULL;
    ByteArray *msg_ba = NULL;
    ByteArray *dec_ba = NULL;
    ByteArray *dec_ossl = NULL;
    ByteArray *enc_cryptonite = NULL;
    uint8_t *p_key = NULL;
    uint8_t *enc = NULL;
    uint8_t *dec = NULL;
    RSA *keypair = RSA_generate_key(1024, 3, NULL, NULL);
    uint8_t msg[] = "sdfsdf";
    int pr_key_len;
    int enc_len;
    int dec_len;
    double time;
    double enc_count = 0;
    PrngCtx *prng = NULL;

    add_mode_name(ctx_tb, "rsa1024-encrypt");
    enc = malloc(RSA_size(keypair));
    dec = malloc(RSA_size(keypair));
    time = get_time();
    do {
        enc_len = RSA_public_encrypt((int)strlen((char*) msg), msg, enc, keypair, RSA_PKCS1_OAEP_PADDING);
        enc_count++;
    } while (((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);

    dec_ossl = ba_alloc_from_uint8(msg, strlen((char*)msg));

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pr_key_len = BIO_pending(pri);

    p_key = malloc(pr_key_len + 1);
    BIO_read(pri, p_key, pr_key_len);
    p_key[pr_key_len] = '\0';

    cryptonite_ctx = malloc(sizeof(RsaXtestCtx));

    prng = test_utils_get_prng();

    ctx = rsa_alloc();
    rsa_init_private_key_from_b64(cryptonite_ctx, p_key);
    enc_os = ba_alloc_from_uint8_be(enc, enc_len);
    rsa_init_decrypt_oaep(ctx, RSA_HASH_SHA1, NULL, cryptonite_ctx->n, cryptonite_ctx->d);
    rsa_decrypt(ctx, enc_os, &dec_ba);

    /*Проверили, что наша реализация расшифровывает данные. Если да, значит можно выводить время и проверять на скорость нашу.*/
    if (equals_ba(dec_ossl, dec_ba)) {
        add_time(ctx_tb, enc_count, OPENSSL);
    } else {
        add_error(ctx_tb, OPENSSL);
        add_error(ctx_tb, CRYPTONITE);
        goto cleanup;
    }

    rsa_init_encrypt_oaep(ctx, prng, RSA_HASH_SHA1, NULL, cryptonite_ctx->n, cryptonite_ctx->e);
    msg_ba = ba_alloc_from_uint8(msg, strlen((char*)msg));
    enc_count = 0;
    time = get_time();
    do {
        ba_free(enc_cryptonite);
        rsa_encrypt(ctx, msg_ba, &enc_cryptonite);
        enc_count++;
    } while (((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(ctx_tb, enc_count, CRYPTONITE);

    xtest_table_print(ctx_tb);
    add_mode_name(ctx_tb, "rsa1024-decypt");

    enc_count = 0;
    time = get_time();
    do {
        dec_len = RSA_private_decrypt(enc_len, enc, dec, keypair, RSA_PKCS1_OAEP_PADDING);
        enc_count++;
    } while (((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    if (!memcpy(msg, dec, dec_len)) {
        return;
    } else {
        add_time(ctx_tb, enc_count, OPENSSL);
    }
    ba_free(dec_ossl);
    dec_ossl = ba_alloc_from_uint8(dec, dec_len);

    enc_count = 0;
    rsa_init_decrypt_oaep(ctx, RSA_HASH_SHA1, NULL, cryptonite_ctx->n, cryptonite_ctx->d);
    time = get_time();
    do {
        ba_free(dec_ba);
        rsa_decrypt(ctx, enc_os, &dec_ba);
        enc_count++;
    } while (((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(ctx_tb, enc_count, CRYPTONITE);

cleanup:

    RSA_free(keypair);
    BIO_free(pri);
    BIO_free(pub);
    free(dec);
    free(p_key);
    free(enc);
    ba_free(enc_os);
    ba_free(dec_ossl);
    ba_free(msg_ba);
    ba_free(enc_cryptonite);
    BA_FREE(cryptonite_ctx->d, cryptonite_ctx->dP, cryptonite_ctx->dQ, cryptonite_ctx->e, cryptonite_ctx->n, cryptonite_ctx->p, cryptonite_ctx->q, cryptonite_ctx->qInv);
    free(cryptonite_ctx);
    ba_free(dec_ba);
}

void xtest_rsa(TableBuilder *ctx)
{
    rsa_atest_ossl_oaep(ctx);
    xtest_table_print(ctx);
}
