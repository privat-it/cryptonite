/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "xtest.h"
#include "dstu4145.h"

#undef ASSERT
#include "bee2/dstu.h"
#include "bee2/util.h"
#include "bee2/hex.h"
#include "bee2/mem.h"
#include "bee2/prng.h"


#define octet uint8_t

typedef struct {
    const char *oid;
    const char a;
    const int f[5];
    const int poly_num;
    const char *n;
    const char *B;
}Dstu4145VerifyHelper;

static Dstu4145VerifyHelper dstu4145_curves_data[] = {
        {
                "1.2.804.2.1.1.1.1.3.1.1.1.2.0",
                1,
                {163, 7,  6, 3, 0},
                5,
                "400000000000000000002BEC12BE2262D39BCF14D",
                "5FF6108462A2DC8210AB403925E638A19C1455D21"
        },
        {
                "1.2.804.2.1.1.1.1.3.1.1.1.2.1",
                1,
                {167, 6,  0, 0, 0},
                3,
                "3FFFFFFFFFFFFFFFFFFFFFB12EBCC7D7F29FF7701F",
                "6EE3CEEB230811759F20518A0930F1A4315A827DAC"
        },
        {
                "1.2.804.2.1.1.1.1.3.1.1.1.2.2",
                0,
                {173, 10, 2, 1, 0},
                5,
                "800000000000000000000189B4E67606E3825BB2831",
                "108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9"
        },
        {
                "1.2.804.2.1.1.1.1.3.1.1.1.2.3",
                1,
                {179, 4,  2, 1, 0},
                5,
                "3FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236EF",
                "4A6E0856526436F2F88DD07A341E32D04184572BEB710"
        },
        {
                "1.2.804.2.1.1.1.1.3.1.1.1.2.4",
                1,
                {191, 9,  0, 0, 0},
                3,
                "40000000000000000000000069A779CAC1DABC6788F7474F",
                "7BC86E2102902EC4D5890E8B6B4981ff27E0482750FEFC03"
        },
        {
                "1.2.804.2.1.1.1.1.3.1.1.1.2.5",
                1,
                {233, 9,  4, 1, 0},
                5,
                "1000000000000000000000000000013E974E72F8A6922031D2603CFE0D7",
                "06973B15095675534C7CF7E64A21BD54EF5DD3B8A0326AA936ECE454D2C"
        },
        {
                "1.2.804.2.1.1.1.1.3.1.1.1.2.6",
                0,
                {257, 12, 0, 0, 0},
                3,
                "800000000000000000000000000000006759213AF182E987D3E17714907D470D",
                "1CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10"
        },
        {
                "1.2.804.2.1.1.1.1.3.1.1.1.2.7",
                1,
                {307, 8,  4, 2, 0},
                5,
                "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC079C2F3825DA70D390FBBA588D4604022B7B7",
                "393C7F7D53666B5054B5E6C6D3DE94F4296C0C599E2E2E241050DF18B6090BDC90186904968BB"
        },
        {
                "1.2.804.2.1.1.1.1.3.1.1.1.2.8",
                1,
                {367, 21, 0, 0, 0},
                3,
                "40000000000000000000000000000000000000000000009C300B75A3FA824F22428FD28CE8812245EF44049B2D49",
                "43FC8AD242B0B7A6F3D1627AD5654447556B47BF6AA4A64B0C2AFE42CADAB8F93D92394C79A79755437B56995136"
        },
        {
                "1.2.804.2.1.1.1.1.3.1.1.1.2.9",
                1,
                {431, 5,  3, 1, 0},
                5,
                "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF",
                "03CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3"
        }
};

static void xtest_verify_core(TableBuilder *builder, Dstu4145VerifyHelper *data)
{
    dstu_params params[1];
    octet privkey[DSTU_SIZE];
    octet pubkey[2 * DSTU_SIZE];
    octet hash[32];
    octet sig[2 * DSTU_SIZE];
    size_t ld;
    octet state[512];
    ByteArray *hash_ba = ba_alloc_from_be_hex_string("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");
    ByteArray *d = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *px = NULL;
    ByteArray *py = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    Dstu4145Ctx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(40);
    size_t curve = data->f[0];
    int a = (int)data->a;
    ByteArray *n = ba_alloc_from_be_hex_string(data->n);
    ByteArray *b = ba_alloc_from_be_hex_string(data->B);
    double time;
    double op_count;
    const char *part_name_1 = "DSTU4145_VERIFY_M";
    const char *part_name_2 = "_PB";
    char mode_name[40] = {' '};


    hexToRev(hash, "09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");

    memset(pubkey, 0, 2 * DSTU_SIZE);
    memset(sig, 0, 2 * DSTU_SIZE);
    memset(privkey, 0, DSTU_SIZE);

    ASSERT_NOT_NULL(prng = prng_alloc(PRNG_MODE_DSTU, seed));

    strcpy(mode_name, part_name_1);
    sprintf(&mode_name[strlen(part_name_1)], "%d", (int)curve);
    strcpy(&mode_name[strlen(part_name_1) + 3], part_name_2);

    add_mode_name(builder, mode_name);

    if (dstuStdParams(params, data->oid) != ERR_OK) {
        goto cleanup;
    }
    // С‚РµСЃС‚ Р�?.1 [РіРµРЅРµСЂР°С†РёСЏ РєР»СЋС‡РµР№]

    ASSERT_TRUE(sizeof(state) >= prngCOMBO_keep());
    prngCOMBOStart(state, utilNonce32());

    dstuGenPoint(params->P, params, prngCOMBOStepG, state);

    if (dstuGenKeypair(privkey, pubkey, params, prngCOMBOStepG, state) != ERR_OK)
        goto cleanup;
    // С‚РµСЃС‚ Р�?.1 [РІС‹СЂР°Р±РѕС‚РєР° Р­Р¦Рџ]
    ld = B_OF_O(2 * DSTU_SIZE);;
    hexToRev(hash, "09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");

    if (dstuSign(sig, params, ld, hash, 32, privkey, prngCOMBOStepG, state) != ERR_OK)
        goto cleanup;

    // С‚РµСЃС‚ Р�?.1 [РїСЂРѕРІРµСЂРєР° Р­Р¦Рџ]
    op_count = 0;
    time = get_time();
    do {
        if (dstuVerify(params, ld, hash, 32, sig, pubkey) != ERR_OK)
            goto cleanup;
        op_count++;
    }while(((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(builder, op_count, CPPCRYPTO);

    ASSERT_NOT_NULL(px = ba_alloc_from_uint8(params->P, O_OF_B(curve)));
    ASSERT_NOT_NULL(py = ba_alloc_from_uint8(&params->P[O_OF_B(curve)], O_OF_B(curve)));


    ASSERT_NOT_NULL(d = ba_alloc_from_uint8(privkey, O_OF_B(curve)));
    ASSERT_NOT_NULL(r = ba_alloc_from_uint8(sig, O_OF_B(curve)));
    ASSERT_NOT_NULL(s = ba_alloc_from_uint8(&sig[DSTU_SIZE], O_OF_B(curve)));

    ASSERT_NOT_NULL(ctx = dstu4145_alloc_pb(data->f, data->poly_num, a, b, n, px, py));
    ASSERT_RET_OK(dstu4145_set_opt_level(ctx, OPT_LEVEL_COMB_11_COMB_11));
    ASSERT_RET_OK(dstu4145_get_pubkey(ctx, d, &qx, &qy));

    ASSERT_RET_OK(dstu4145_init_verify(ctx, qx, qy));

    op_count = 0;
    time = get_time();
    do {
        dstu4145_verify(ctx, hash_ba, r, s);
        op_count++;
    }while(((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(builder, op_count, CRYPTONITE_DSTU);

cleanup:

    xtest_table_print(builder);

    prng_free(prng);
    dstu4145_free(ctx);
    BA_FREE(qx, qy, hash_ba, r, s, d, seed, px, py);
}

static void xtest_sign_core(TableBuilder *builder, Dstu4145VerifyHelper *data)
{
    dstu_params params[1];
    octet privkey[DSTU_SIZE];
    octet pubkey[2 * DSTU_SIZE];
    octet hash[32];
    octet sig[2 * DSTU_SIZE];
    size_t ld;
    octet state[512];
    ByteArray *hash_ba = ba_alloc_from_be_hex_string("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");
    ByteArray *d = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *px = NULL;
    ByteArray *py = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    Dstu4145Ctx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(40);
    size_t curve = data->f[0];
    int a = (int)data->a;
    ByteArray *n = ba_alloc_from_be_hex_string(data->n);
    ByteArray *b = ba_alloc_from_be_hex_string(data->B);
    double time;
    double op_count;
    const char *part_name_1 = "DSTU4145_SIGN_M";
    const char *part_name_2 = "_PB....";
    char mode_name[40];

    hexToRev(hash, "09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");

    memset(pubkey, 0, 2 * DSTU_SIZE);
    memset(sig, 0, 2 * DSTU_SIZE);
    memset(privkey, 0, DSTU_SIZE);

    ASSERT_NOT_NULL(prng = prng_alloc(PRNG_MODE_DSTU, seed));

    strcpy(mode_name, part_name_1);
    sprintf(&mode_name[strlen(part_name_1)], "%d", (int)curve);
    strcpy(&mode_name[strlen(part_name_1) + 3], part_name_2);

    add_mode_name(builder, mode_name);

    if (dstuStdParams(params, data->oid) != ERR_OK) {
        goto cleanup;
    }
    // С‚РµСЃС‚ Р�?.1 [РіРµРЅРµСЂР°С†РёСЏ РєР»СЋС‡РµР№]

    ASSERT_TRUE(sizeof(state) >= prngCOMBO_keep());
    prngCOMBOStart(state, utilNonce32());

    dstuGenPoint(params->P, params, prngCOMBOStepG, state);

   // С‚РµСЃС‚ Р�?.1 [РІС‹СЂР°Р±РѕС‚РєР° Р­Р¦Рџ]
    ld = B_OF_O(2 * DSTU_SIZE);;
    hexToRev(hash, "09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");

    ASSERT_NOT_NULL(px = ba_alloc_from_uint8(params->P, O_OF_B(curve)));
    ASSERT_NOT_NULL(py = ba_alloc_from_uint8(&params->P[O_OF_B(curve)], O_OF_B(curve)));

    ASSERT_NOT_NULL(ctx = dstu4145_alloc_pb(data->f, data->poly_num, a, b, n, px, py));
    ASSERT_RET_OK(dstu4145_set_opt_level(ctx, OPT_LEVEL_COMB_11_COMB_11));
    ASSERT_RET_OK(dstu4145_generate_privkey(ctx, prng, &d));
    ASSERT_RET_OK(dstu4145_get_pubkey(ctx, d, &qx, &qy));

    ASSERT_RET_OK(dstu4145_init_sign(ctx, d, prng));

    op_count = 0;
    time = get_time();
    do {
        ba_free(r);
        ba_free(s);
        ASSERT_RET_OK(dstu4145_sign(ctx, hash_ba, &r, &s));
        op_count++;
    }while(((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(builder, op_count, CRYPTONITE_DSTU);

    ASSERT_RET_OK(dstu4145_init_verify(ctx, qx, qy));
    ASSERT_RET_OK(dstu4145_verify(ctx, hash_ba, r, s));

    memcpy(privkey, ba_get_buf(d), ba_get_len(d));
    memcpy(sig, ba_get_buf(r), ba_get_len(r));
    memcpy(&sig[DSTU_SIZE], ba_get_buf(s), ba_get_len(s));
    memcpy(pubkey, ba_get_buf(qx), ba_get_len(qx));
    memcpy(&pubkey[ba_get_len(qx)], ba_get_buf(qy), ba_get_len(qy));

    if (dstuVerify(params, ld, hash, 32, sig, pubkey) != ERR_OK) {
        goto cleanup;
    }

    op_count = 0;
    time = get_time();
    do {
        if (dstuSign(sig, params, ld, hash, 32, privkey, prngCOMBOStepG, state) != ERR_OK) {
            goto cleanup;
        }
        op_count++;
    }while(((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(builder, op_count, CPPCRYPTO);
cleanup:

    xtest_table_print(builder);

    prng_free(prng);
    dstu4145_free(ctx);
    BA_FREE(qx, qy, hash_ba, r, s, d, seed, px, py);
}

#define XTEST_DSTU4145_CORE(dstu4145_curves_data, func)\
{\
    size_t i = 0;\
    for (i = 0; i < sizeof(dstu4145_curves_data)/sizeof(Dstu4145VerifyHelper); i++) {\
        func(ctx, &dstu4145_curves_data[i]);\
    }\
}\

void xtest_dstu4145(TableBuilder *ctx)
{
    XTEST_DSTU4145_CORE(dstu4145_curves_data, xtest_verify_core);
    XTEST_DSTU4145_CORE(dstu4145_curves_data, xtest_sign_core);

#undef octet
}
