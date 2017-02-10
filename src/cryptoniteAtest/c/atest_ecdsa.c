/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "atest.h"
#include "ecdsa.h"
#include "rs.h"

/*Тестовые данные для проверки сгенерированы с помощью openssl.
 https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations
*/
static void test_ecdsa_verify(EcdsaParamsId id,
        const ByteArray *qx, const ByteArray *qy, const ByteArray *hash,
        const ByteArray *r, const ByteArray *s)
{
    EcdsaCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = ecdsa_alloc(id));

    ASSERT_RET_OK(ecdsa_init_verify(ctx, qx, qy));
    ASSERT_RET_OK(ecdsa_verify(ctx, hash, r, s));

cleanup:

    ecdsa_free(ctx);
}

static void test_ecdsa_verify_192(void)
{
    ByteArray *qx = ba_alloc_from_be_hex_string("8CF149E91FDFE308B66FAD9F82BBB098576FEA6BEACA7377");
    ByteArray *qy = ba_alloc_from_be_hex_string("AB6F6331C39C220BEA716E93722217FFFE727A962402C66D");
    ByteArray *hash = ba_alloc_from_le_hex_string("ac9c2a2ca4eb7c4a9039e658e7f8d7b11aef1f34");
    ByteArray *r = ba_alloc_from_be_hex_string("D693C651109B4EDE0FDAB92779F74D5D8965A16C5881BEED");
    ByteArray *s = ba_alloc_from_be_hex_string("5BF193AD07A2FE10EEDD70D43A9B14404E3C284907825407");

    test_ecdsa_verify(ECDSA_PARAMS_ID_SEC_P192_R1, qx, qy, hash, r, s);

    BA_FREE(s, r, qx, qy, hash);
}

static void test_ecdsa_verify_224(void)
{
    ByteArray *qx = ba_alloc_from_be_hex_string("0BF55F03595A7AFB3378969C65021E802C43318A99381F58B01A7DD6");
    ByteArray *qy = ba_alloc_from_be_hex_string("8B5A54E16C41D12B12DB0E9356B4A0AF8FB9C073F23FE753FD16FAEC");
    ByteArray *hash = ba_alloc_from_le_hex_string("ac9c2a2ca4eb7c4a9039e658e7f8d7b11aef1f34");
    ByteArray *r = ba_alloc_from_be_hex_string("8C55714BA398EE461622AD1D03A0C7F754887DA1A7D169AE1DA2122B");
    ByteArray *s = ba_alloc_from_be_hex_string("1B6F7AA600D086E5F89C22BCE772D09FCEC75EF996CA3429694A860D");

    test_ecdsa_verify(ECDSA_PARAMS_ID_SEC_P224_R1, qx, qy, hash, r, s);

    BA_FREE(s, r, qx, qy, hash);
}

static void test_ecdsa_verify_256(void)
{
    ByteArray *qx = ba_alloc_from_be_hex_string("772B443BB07ACD53FB22E0F014170EB12E74D0EBBA1581CF4D23F4E6B6CFD3D6");
    ByteArray *qy = ba_alloc_from_be_hex_string("2B0F69465776093479E5B7C73549DF226ACC333F7B5D961186394D44C12045F3");
    ByteArray *hash = ba_alloc_from_le_hex_string("ac9c2a2ca4eb7c4a9039e658e7f8d7b11aef1f34");
    ByteArray *r = ba_alloc_from_be_hex_string("75983BD5D6F48856F3E9A54CDEAA0AD9A43E078E8F8217384B2C185381D818E1");
    ByteArray *s = ba_alloc_from_be_hex_string("B8DAE388F45FE1842209493BF38CE9AF9DCEBD2A0DA5486D136768C2A06D3F63");

    test_ecdsa_verify(ECDSA_PARAMS_ID_SEC_P256_R1, qx, qy, hash, r, s);

    BA_FREE(s, r, qx, qy, hash);
}

static void test_ecdsa_verify_384(void)
{
    ByteArray *qx = ba_alloc_from_be_hex_string(
            "C928368C7C90EE01353556847951E2E45E1ABFA2533D2C70EB27B203D8CFE6B66A2C9D8478929D5CB686B457036BDCA1");
    ByteArray *qy = ba_alloc_from_be_hex_string(
            "C9D46DDBDFE2DAB2CFCFC808B8F82393AFEB735F14C5D60616B7BE8336092E04ECD87913214CB9E3A359F33B5C600B0D");
    ByteArray *hash = ba_alloc_from_le_hex_string("ac9c2a2ca4eb7c4a9039e658e7f8d7b11aef1f34");
    ByteArray *r = ba_alloc_from_be_hex_string(
            "786A77C1E35E1B0B8855621938D171A492B51F649E3EB67552DF82030854836D4943A7FE688B2906ABC528D2418F6F5A");
    ByteArray *s = ba_alloc_from_be_hex_string(
            "A9E00641687C1DCF0E09F25C518EFB627687E198F990CAE365F192268F38122B3E5C905E29981B5468C630BE05840F4C");

    test_ecdsa_verify(ECDSA_PARAMS_ID_SEC_P384_R1, qx, qy, hash, r, s);

    BA_FREE(s, r, qx, qy, hash);
}

static void test_ecdsa_verify_521(void)
{
    ByteArray *qx = ba_alloc_from_be_hex_string(
            "009C4CD55935E8C54F60DE76CF72CC260D65DEB4E3D0D526D9FF825E309B497115CB4723357A5819726E808A590302FD3C776100BF003F81B587BAF98DA180706D2F");
    ByteArray *qy = ba_alloc_from_be_hex_string(
            "01880D89C859724934B8F61ECB21D889D9BEA11F72738735E29C35448DD980F5BEF143C4630384417FB0B7B1013E2465AEEE98D4F3F3D997AF29D31CA1ABC92DD343");
    ByteArray *hash = ba_alloc_from_le_hex_string("ac9c2a2ca4eb7c4a9039e658e7f8d7b11aef1f34");
    ByteArray *r = ba_alloc_from_be_hex_string(
            "003B348A28547ECBB32C4FA4A0C43AC5514581FB26731C7607715270C992FC2D4A4DED1D13E7DC0C80906A341100F9A80B580DC9901351EBB4EB8737ED74BC3A9D96");
    ByteArray *s = ba_alloc_from_be_hex_string(
            "01FB38E44EC90E55D8DE0DF5836DE66C7C25C7FD3E3121C2F4C90FDB0863793858B55AE1AFBC7EE5993075350527E3A765C45DACBB716708684EB92D0926BED3E9A5");

    test_ecdsa_verify(ECDSA_PARAMS_ID_SEC_P521_R1, qx, qy, hash, r, s);

    BA_FREE(s, r, qx, qy, hash);
}

void atest_ecdsa(void)
{
    size_t old_error = error_count;

    test_ecdsa_verify_192();
    test_ecdsa_verify_224();
    test_ecdsa_verify_256();
    test_ecdsa_verify_384();
    test_ecdsa_verify_521();

    if (error_count == old_error) {
        msg_print_atest("ECDSA", "[verify]", "OK");
    } else {
        msg_print_atest("ECDSA", "", "FAILED");
    }

    return;
}
