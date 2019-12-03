/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <time.h>

#include "utest.h"
#include "cert.h"
#include "cert_engine.h"
#include "asn1_utils.h"
#include "aid.h"
#include "cryptonite_manager.h"
#include "certificate_request_engine.h"
#include "certification_request.h"
#include "rs.h"
#include "crl.h"
#include "spki.h"
#include "ext.h"
#include "exts.h"

//Cамоподписанный сертификат
static void test_ecert_generate(void)
{
    Certificate_t *cert = NULL;
    CertificateEngine *cert_engine_ctx = NULL;
    CertificationRequest_t *cert_request = NULL;
    Extensions_t *exts = NULL;

    DigestAdapter *da = NULL;
    SignAdapter *sa = NULL;

    time_t not_before;
    time_t not_after;
    time_t act_not_before;
    time_t act_not_after;
    struct tm *timeinfo = NULL;

    ByteArray *private_key = NULL;
    Dstu4145Ctx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(40);

    AlgorithmIdentifier_t *signature_aid = NULL;
    AlgorithmIdentifier_t *alg = NULL;
    ByteArray *sign_ba = ba_alloc_from_le_hex_string("300d060b2a86240201010101030101");
    ByteArray *alg_ba =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301013051060d2a8624020101010103010102060440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");
    CertificateRequestEngine *cert_request_eng = NULL;

    char dns[] = "ca.ua";
    char email[] = "info@ca.ua";
    char subject_attr[] = "{1.2.804.2.1.1.1.11.1.4.1.1=292431128}";
    const char subject[] =
            "{O=Петров Василь Олександрович ФОП}"
            "{OU=Керiвництво}"
            "{CN=Петров В.О.}"
            "{SRN=Петров}"
            "{GN=Василь Олександрович}"
            "{SN=9834567812}"
            "{C=UA}"
            "{L=Днiпропетровськ}"
            "{ST=Дніпропетровська}"
            "{T=Підприємець}";

    const unsigned char serial[] = {
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00,
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00
    };

    ByteArray *serial_ba = ba_alloc_from_uint8(serial, 20);

    /* UTC time 26.01.23 22:00:00. */
    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 123;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_after = mktime(timeinfo);
    free(timeinfo);

    /* UTC time 26.01.13 22:00:00. */
    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_before = mktime(timeinfo);
    free(timeinfo);

    ASSERT_RET_OK(rs_std_next_bytes(seed));
    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB));
    ASSERT_NOT_NULL(prng = prng_alloc(PRNG_MODE_DSTU, seed));
    ASSERT_RET_OK(dstu4145_generate_privkey(ctx, prng, &private_key));

    ASSERT_NOT_NULL(signature_aid = aid_alloc());
    ASSERT_RET_OK(aid_decode(signature_aid, sign_ba));
    ASSERT_NOT_NULL(alg = aid_alloc());
    ASSERT_RET_OK(aid_decode(alg, alg_ba));

    ASSERT_RET_OK(digest_adapter_init_default(&da));
    ASSERT_RET_OK(sign_adapter_init_by_aid(private_key, signature_aid, alg, &sa));

    ASSERT_RET_OK(ecert_request_alloc(sa, &cert_request_eng));
    ASSERT_RET_OK(ecert_request_set_subj_name(cert_request_eng, subject));
    ASSERT_RET_OK(ecert_request_set_subj_alt_name(cert_request_eng, dns, email));
    ASSERT_RET_OK(ecert_request_set_subj_dir_attr(cert_request_eng, subject_attr));
    ASSERT_RET_OK(ecert_request_generate(cert_request_eng, &cert_request));

    ASSERT_NOT_NULL(exts = exts_alloc());

    ASSERT_RET_OK(ecert_alloc(sa, da, true, &cert_engine_ctx));
    ASSERT_RET_OK(ecert_generate(cert_engine_ctx, cert_request, 2, serial_ba, &not_before, &not_after, exts, &cert));

    ASSERT_RET_OK(cert_get_not_before(cert, &act_not_before));
    ASSERT_RET_OK(cert_get_not_after(cert, &act_not_after));
    ASSERT_TRUE(difftime(not_before, act_not_before) == 0);
    ASSERT_TRUE(difftime(not_after, act_not_after) == 0);

cleanup:

    dstu4145_free(ctx);
    prng_free(prng);

    cert_free(cert);
    ecert_free(cert_engine_ctx);
    creq_free(cert_request);
    aid_free(signature_aid);
    aid_free(alg);
    ecert_request_free(cert_request_eng);
    exts_free(exts);

    sign_adapter_free(sa);
    digest_adapter_free(da);

    BA_FREE(serial_ba, alg_ba, sign_ba, private_key, seed);
}

#if defined(__LP64__) || defined(_WIN32)

static void test_ecert_generate_2(void)
{
    Certificate_t *cert = cert_alloc();
    Certificate_t *act_cert = NULL;
    CertificateEngine *cert_engine_ctx = NULL;
    CertificationRequest_t *cert_request = NULL;
    Extensions_t *exts = NULL;

    DigestAdapter *da = NULL;
    SignAdapter *sa = NULL;
    CertificateRequestEngine *cert_request_eng = NULL;

    time_t not_before;
    time_t not_after;
    time_t act_not_before;
    time_t act_not_after;
    struct tm *timeinfo = NULL;

    ByteArray *private_key =
            ba_alloc_from_le_hex_string("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");
    ByteArray *buffer = NULL;

    char dns[] = "ca.ua";
    char email[] = "info@ca.ua";
    char subject_attr[] = "{1.2.804.2.1.1.1.11.1.4.1.1=292431128}";
    const char subject[] =
            "{O=Петров Василь Олександрович ФОП}"
            "{OU=Керiвництво}"
            "{CN=Петров В.О.}"
            "{SRN=Петров}"
            "{GN=Василь Олександрович}"
            "{SN=9834567812}"
            "{C=UA}"
            "{L=Днiпропетровськ}"
            "{ST=Дніпропетровська}"
            "{T=Підприємець}";

    const unsigned char serial[] = {
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00,
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00
    };

    ByteArray *serial_ba = ba_alloc_from_uint8(serial, 20);

    // UTC time 26.01.53 22:00:00.
    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 153;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_after = mktime(timeinfo);
    free(timeinfo);

    // UTC time 26.01.13 22:00:00.
    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_before = mktime(timeinfo);
    free(timeinfo);

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/certificate257.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));

    ASSERT_RET_OK(digest_adapter_init_default(&da));
    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert, &sa));

    ASSERT_RET_OK(ecert_request_alloc(sa, &cert_request_eng));
    ASSERT_RET_OK(ecert_request_set_subj_name(cert_request_eng, subject));
    ASSERT_RET_OK(ecert_request_set_subj_alt_name(cert_request_eng, dns, email));
    ASSERT_RET_OK(ecert_request_set_subj_dir_attr(cert_request_eng, subject_attr));
    ASSERT_RET_OK(ecert_request_generate(cert_request_eng, &cert_request));

    ASSERT_NOT_NULL(exts = exts_alloc());

    ASSERT_RET_OK(ecert_alloc(sa, da, false, &cert_engine_ctx));

    cert_free(cert);
    cert = NULL;

    ASSERT_RET_OK(ecert_generate(cert_engine_ctx, cert_request, 2, serial_ba, &not_before, &not_after, exts, &cert));

    ASSERT_RET_OK(cert_get_not_before(cert, &act_not_before));
    ASSERT_RET_OK(cert_get_not_after(cert, &act_not_after));
    ASSERT_TRUE(difftime(not_before, act_not_before) == 0);
    ASSERT_TRUE(difftime(not_after, act_not_after) == 0);

cleanup:

    cert_free(cert);
    cert_free(act_cert);
    ecert_free(cert_engine_ctx);
    creq_free(cert_request);
    exts_free(exts);

    sign_adapter_free(sa);
    digest_adapter_free(da);
    ecert_request_free(cert_request_eng);

    BA_FREE(serial_ba, private_key, buffer);
}

#endif

void utest_cert_engine(void)
{
    PR("%s\n", __FILE__);

    test_ecert_generate();

#if defined(__LP64__) || defined(_WIN32)
    test_ecert_generate_2();
#endif
}
