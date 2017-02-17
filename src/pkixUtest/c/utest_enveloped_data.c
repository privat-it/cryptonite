/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "enveloped_data.h"
#include "asn1_utils.h"
#include "cert.h"
#include "aid.h"
#include "content_info.h"
#include "cryptonite_manager.h"
#include "pkix_errors.h"

static EnvelopedData_t *load_test_data(void)
{
    EnvelopedData_t *envdata = NULL;
    ByteArray *decoded = NULL;

    ASSERT_NOT_NULL(envdata = env_data_alloc());
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/enveloped_data.dat", &decoded));
    ASSERT_RET_OK(env_data_decode(envdata, decoded));
cleanup:
    BA_FREE(decoded);
    return envdata;
}

static void test_encode(EnvelopedData_t *envdata)
{
    EnvelopedData_t *envdata_tmp = NULL;
    ByteArray *decoded = NULL;
    ByteArray *encoded = NULL;

    envdata_tmp = env_data_alloc();

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/enveloped_data.dat", &decoded));

    ASSERT_RET_OK(env_data_encode(envdata, &encoded));
    ASSERT_NOT_NULL(encoded);

    ASSERT_RET_OK(env_data_decode(envdata_tmp, encoded));

    ASSERT_EQUALS_ASN(&EnvelopedData_desc, envdata, envdata_tmp);
cleanup:
    BA_FREE(decoded, encoded);
    env_data_free(envdata_tmp);
}

static void test_has_issuer_cert(EnvelopedData_t *envdata)
{
    bool answ;

    ASSERT_RET_OK(env_data_has_originator_cert(envdata, &answ));
    ASSERT_TRUE(answ == false);

cleanup:
    return;
}

static void test_env_data_get_originator_cert(void)
{
    EnvelopedData_t *env_data = env_data_alloc();
    Certificate_t *originator_cert = NULL;

    ASSERT_RET(RET_PKIX_NO_CERTIFICATE, env_data_get_originator_cert(env_data, &originator_cert));

cleanup:

    env_data_free(env_data);
    cert_free(originator_cert);
}

static void test_env_data_init(void)
{
    EnvelopedData_t *env_data = env_data_alloc();
    INTEGER_t *version = NULL;
    OriginatorInfo_t *originator_info = NULL;
    RecipientInfos_t *recipients = NULL;
    EncryptedContentInfo_t *encr_content_info = NULL;
    Attributes_t *attrs = NULL;

    ASSERT_RET_OK(asn_create_integer_from_long(2, &version));
    ASSERT_ASN_ALLOC(recipients);
    ASSERT_ASN_ALLOC(encr_content_info);
    ASSERT_ASN_ALLOC(attrs);
    ASSERT_ASN_ALLOC(originator_info);

    ASSERT_RET_OK(env_data_init(env_data, version, originator_info, recipients, encr_content_info, attrs));

    ASSERT_EQUALS_ASN(&INTEGER_desc, &env_data->version, version);
    ASSERT_EQUALS_ASN(&OriginatorInfo_desc, env_data->originatorInfo, originator_info);
    ASSERT_EQUALS_ASN(&Attributes_desc, env_data->unprotectedAttrs, attrs);
    ASSERT_EQUALS_ASN(&RecipientInfos_desc, &env_data->recipientInfos, recipients);
    ASSERT_EQUALS_ASN(&EncryptedContentInfo_desc, &env_data->encryptedContentInfo, encr_content_info);

cleanup:

    env_data_free(env_data);
    ASN_FREE(&INTEGER_desc, version);
    ASN_FREE(&RecipientInfos_desc, recipients);
    ASN_FREE(&EncryptedContentInfo_desc, encr_content_info);
    ASN_FREE(&OriginatorInfo_desc, originator_info);
    ASN_FREE(&Attributes_desc, attrs);
}

static void test_env_data_init_2(void)
{
    EnvelopedData_t *env_data = env_data_alloc();
    INTEGER_t *version = NULL;
    OriginatorInfo_t *originator_info = NULL;
    RecipientInfos_t *recipients = NULL;
    EncryptedContentInfo_t *encr_content_info = NULL;
    Attributes_t *attrs = NULL;

    ASSERT_RET_OK(asn_create_integer_from_long(2, &version));
    ASSERT_ASN_ALLOC(recipients);
    ASSERT_ASN_ALLOC(encr_content_info);
    ASSERT_ASN_ALLOC(attrs);
    ASSERT_ASN_ALLOC(originator_info);

    ASSERT_RET(RET_INVALID_PARAM, env_data_init(NULL, version, originator_info, recipients, encr_content_info, attrs));
    ASSERT_RET(RET_INVALID_PARAM, env_data_init(env_data, version, originator_info, NULL, encr_content_info, attrs));
    ASSERT_RET(RET_INVALID_PARAM, env_data_init(env_data, version, originator_info, recipients, NULL, attrs));

cleanup:

    env_data_free(env_data);
    ASN_FREE(&INTEGER_desc, version);
    ASN_FREE(&RecipientInfos_desc, recipients);
    ASN_FREE(&EncryptedContentInfo_desc, encr_content_info);
    ASN_FREE(&OriginatorInfo_desc, originator_info);
    ASN_FREE(&Attributes_desc, attrs);
}

static void test_env_get_content_encryption_aid(void)
{
    AlgorithmIdentifier_t *encr_aid = NULL;

    ASSERT_RET(RET_INVALID_PARAM, env_get_content_encryption_aid(NULL, &encr_aid));
    ASSERT_TRUE(encr_aid == NULL);

cleanup:

    ASN_FREE(&AlgorithmIdentifier_desc, encr_aid);
}

void utest_enveloped_data(void)
{
    PR("%s\n", __FILE__);

    EnvelopedData_t *envdata = NULL;

    envdata = load_test_data();

    if (envdata) {
        test_encode(envdata);
        test_has_issuer_cert(envdata);
        test_env_data_get_originator_cert();
        test_env_data_init();
        test_env_data_init_2();
        test_env_get_content_encryption_aid();
        //TODO: Добавить данные с OriginatorInfo
    }

    env_data_free(envdata);
}
