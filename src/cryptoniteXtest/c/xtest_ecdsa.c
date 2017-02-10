/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "openssl/evp.h"
#include "openssl/obj_mac.h"
#include "openssl/ecdsa.h"

#include "xtest.h"
#include "ecdsa.h"

static void test_ecdsa(TableBuilder *ctx_tb, EcdsaParamsId id)
{
    ECDSA_SIG *sig = NULL;
    const BIGNUM *privkey = NULL;
    EC_KEY *eckey = NULL;
    char *r = NULL;
    char *s = NULL;
    char *d = NULL;
    ByteArray *r_ba = NULL;
    ByteArray *s_ba = NULL;
    ByteArray *r_cryptonite = NULL;
    ByteArray *s_cryptonite = NULL;
    ByteArray *qx_ba = NULL;
    ByteArray *qy_ba = NULL;
    ByteArray *d_ba = NULL;
    ByteArray *hash_ba = NULL;
    EcdsaCtx *ecdsa_ctx = NULL;
    uint8_t digest[20];
    PrngCtx *prng_ctx = test_utils_get_prng();
    int ret = RET_OK;
    double time;
    size_t i = 0;
    char ecdsa_sign_name[20] = "EcdsaSign";
    char ecdsa_verify_name[20] = "EcdsaVerify";

    switch (id) {
        case ECDSA_PARAMS_ID_SEC_P192_R1:
            ASSERT_NOT_NULL(eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime192v1));
            strcpy(&ecdsa_sign_name[strlen(ecdsa_sign_name)], "192");
            strcpy(&ecdsa_verify_name[strlen(ecdsa_verify_name)], "192");
            break;
        case ECDSA_PARAMS_ID_SEC_P224_R1:
            ASSERT_NOT_NULL(eckey = EC_KEY_new_by_curve_name(NID_secp224r1));
            strcpy(&ecdsa_sign_name[strlen(ecdsa_sign_name)], "224");
            strcpy(&ecdsa_verify_name[strlen(ecdsa_verify_name)], "224");
            break;
        case ECDSA_PARAMS_ID_SEC_P256_R1:
            ASSERT_NOT_NULL(eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
            strcpy(&ecdsa_sign_name[strlen(ecdsa_sign_name)], "256");
            strcpy(&ecdsa_verify_name[strlen(ecdsa_verify_name)], "256");
            break;
        case ECDSA_PARAMS_ID_SEC_P384_R1:
            ASSERT_NOT_NULL(eckey = EC_KEY_new_by_curve_name(NID_secp384r1));
            strcpy(&ecdsa_sign_name[strlen(ecdsa_sign_name)], "384");
            strcpy(&ecdsa_verify_name[strlen(ecdsa_verify_name)], "384");
            break;
        case ECDSA_PARAMS_ID_SEC_P521_R1:
            ASSERT_NOT_NULL(eckey = EC_KEY_new_by_curve_name(NID_secp521r1));
            strcpy(&ecdsa_sign_name[strlen(ecdsa_sign_name)], "521");
            strcpy(&ecdsa_verify_name[strlen(ecdsa_verify_name)], "521");
            break;
        default:
            ASSERT_RET_OK(RET_INVALID_PARAM);
    }

    add_mode_name(ctx_tb, ecdsa_sign_name);

    for (i = 0; i < sizeof(digest); i++) {
        digest[i] = i & 0xff;
    }

    ASSERT_NOT_NULL(hash_ba = ba_alloc_from_uint8(digest, sizeof(digest)));
    //Генерируем ключ
    EC_KEY_generate_key(eckey);

    //Подписываем
    i = 0;
    time = get_time();
    do {
        ECDSA_SIG_free(sig);
        sig = ECDSA_do_sign(digest, sizeof(digest), eckey);
        i++;
    }while(((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(ctx_tb, (double)i, OPENSSL);
    //Проверяем
    ret = ECDSA_do_verify(digest, sizeof(digest), sig, eckey);
    if (ret != 1) {
        ASSERT_RET_OK(RET_VERIFY_FAILED);
    }

    privkey = EC_KEY_get0_private_key(eckey);

    //Переводим в криптонитопонятный вид
    r = BN_bn2hex(sig->r);
    s = BN_bn2hex(sig->s);
    d = BN_bn2hex(privkey);

    r_ba = ba_alloc_from_be_hex_string(r);
    s_ba = ba_alloc_from_be_hex_string(s);
    d_ba = ba_alloc_from_be_hex_string(d);

    ASSERT_NOT_NULL(ecdsa_ctx = ecdsa_alloc(id));
    ASSERT_RET_OK(ecdsa_set_opt_level(ecdsa_ctx, OPT_LEVEL_COMB_11_COMB_11));
    ASSERT_RET_OK(ecdsa_init_sign(ecdsa_ctx, d_ba, prng_ctx));

    i = 0;
    time = get_time();
    do {
        ba_free(r_cryptonite);
        ba_free(s_cryptonite);
        r_cryptonite = NULL;
        s_cryptonite = NULL;
        ASSERT_RET_OK(ecdsa_sign(ecdsa_ctx, hash_ba, &r_cryptonite, &s_cryptonite));
        i++;
    }while(((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(ctx_tb, (double)i, CRYPTONITE);

    add_mode_name(ctx_tb, ecdsa_verify_name);
    i = 0;
    time = get_time();
    do {
        ret = ECDSA_do_verify(digest, sizeof(digest), sig, eckey);
        if (ret != 1) {
            ASSERT_RET_OK(RET_VERIFY_FAILED);
        }
        i++;
    }while(((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(ctx_tb, (double)i, OPENSSL);

    ASSERT_RET_OK(ecdsa_get_pubkey(ecdsa_ctx, d_ba, &qx_ba, &qy_ba));
    ASSERT_RET_OK(ecdsa_init_verify(ecdsa_ctx, qx_ba, qy_ba));

    i = 0;
    time = get_time();
    do {
        ASSERT_RET_OK(ecdsa_verify(ecdsa_ctx, hash_ba, r_ba, s_ba));
        i++;
    }while(((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(ctx_tb, (double)i, CRYPTONITE);

cleanup:

    if ((ret != 1) && (ret != RET_OK)) {
        add_error(ctx_tb, CRYPTONITE);
        add_error(ctx_tb, OPENSSL);
    }

    xtest_table_print(ctx_tb);

    ECDSA_SIG_free(sig);
    ecdsa_free(ecdsa_ctx);
    EC_KEY_free(eckey);
    BA_FREE(r_ba, s_ba, qx_ba, qy_ba, r_cryptonite, s_cryptonite, hash_ba);
}

void xtest_ecdsa(TableBuilder *ctx)
{
    test_ecdsa(ctx, ECDSA_PARAMS_ID_SEC_P192_R1);
    test_ecdsa(ctx, ECDSA_PARAMS_ID_SEC_P224_R1);
    test_ecdsa(ctx, ECDSA_PARAMS_ID_SEC_P256_R1);
    test_ecdsa(ctx, ECDSA_PARAMS_ID_SEC_P384_R1);
    test_ecdsa(ctx, ECDSA_PARAMS_ID_SEC_P521_R1);
}
