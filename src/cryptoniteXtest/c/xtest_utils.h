/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef XTEST_UTILS_H
#define XTEST_UTILS_H

#ifdef __cplusplus
extern "C"{
#endif

#include <string.h>

#include "pthread_internal.h"
#include "openssl/des.h"
#include "aes.h"
#include "openssl/aes.h"
#include "test_utils.h"

typedef enum{
    OPENSSL = 0,
    GCRYPT,
    CRYPTONITE
} LIBS_XTEST;

typedef enum{
    CPPCRYPTO = 0,
    CRYPTONITE_DSTU
} LIBS_XTEST_DSTU;

pthread_mutex_t lock;

typedef enum{
    SHA_HASH = 0,
    RIPEMD_HASH,
    AES,
    DES,
    DSTU,
    CIPHER
} AlgType;

struct Xtest_st{
    ByteArray *data_ba;
    uint8_t *data;
    AlgType alg_type;

    union{
        struct{
            uint8_t key_data[64];
            ByteArray *key_128_ba;
            ByteArray *key_256_ba;
            ByteArray *key_512_ba;
            ByteArray *iv_128_ba;
            ByteArray *iv_256_ba;
            ByteArray *iv_512_ba;
        } DSTU;

        struct{
            AES_KEY key_ossl[3];
            uint8_t keys[3][32];
            ByteArray *key_128_ba;
            ByteArray *key_192_ba;
            ByteArray *key_256_ba;
        } AES;

        struct{
            AES_KEY key_ossl[5];
            uint8_t keys[5][64];
            ByteArray *key_160_ba;
            ByteArray *key_224_ba;
            ByteArray *key_256_ba;
            ByteArray *key_384_ba;
            ByteArray *key_512_ba;
        } SHA;

        struct{
            uint8_t keys[24];
            uint8_t iv[8];
            ByteArray *key_ba;
            ByteArray *iv_ba;
            /*ossl_structs*/
            DES_key_schedule k1;
            DES_key_schedule k2;
            DES_key_schedule k3;
        } DES;
    } CipherType;
};

typedef struct{
    uint8_t *data;
    ByteArray *data_ba;
    ByteArray *res_cryptonite;
    ByteArray *res_ossl;
    ByteArray *res_gcrypt;
    size_t algo;
    size_t loop_num;
    double time;
} ThreadSt;

typedef struct Xtest_st XtestSt;

typedef struct{
    XtestSt *cipher_data;
    ThreadSt *thread_data;
} ThreadHelper;

#define xtest_check()                                       \
{                                                           \
    if(!equals_ba(res_gcrypt_ba, res_ossl_ba)) {            \
        if (!equals_ba(res_ba, res_ossl_ba)) {              \
            add_error(ctx_tb, OPENSSL);                     \
        }                                                   \
        if (!equals_ba(res_ba, res_gcrypt_ba)) {            \
            add_error(ctx_tb, GCRYPT);                      \
        }                                                   \
        tot_errors++;                                       \
    } else {                                                \
        if (!equals_ba(res_ba, res_ossl_ba)) {              \
           add_error(ctx_tb, CRYPTONITE);                   \
           tot_errors++;                                    \
        }                                                   \
        if (!equals_ba(res_ba, res_gcrypt_ba)) {            \
           add_error(ctx_tb, CRYPTONITE);                   \
           tot_errors++;                                    \
        }                                                   \
    }                                                       \
}

/*For 4b tests*/

void AES_generete_data(XtestSt *ctx);
void SHA_generete_data(XtestSt *ctx);
void DES_generete_data(XtestSt *ctx);
void DSTU_generete_data(XtestSt *ctx);

XtestSt* rnd_generate(size_t size_mode);

void xtest_alg_free(XtestSt *ctx);
void rnd_data_free(XtestSt *ctx);

void add_to_loop(ThreadSt *arg, ByteArray *data_ba, uint8_t *data, int gcrypt_mod);
void thread_st_add(ThreadHelper *ctx, ThreadSt *thrd_data, XtestSt *cip_data);
void thread_free(ThreadHelper *ctx);
void free_loop(ThreadSt *arg);

void xtest_table_print(TableBuilder *ctx);

void thrd_num_retrieve(void);

#ifdef __cplusplus
}
#endif

#endif /* XTEST_UTILS_H */

