/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "oids.h"
#include "pkix_utils.h"

static void test_oids_get_supported_extention(void)
{
    const OidNumbers *ext = NULL;
    OBJECT_IDENTIFIER_t *exp_oid = NULL;

    ASSERT_RET_OK(asn_create_oid_from_text("2.5.29.9", &exp_oid));
    ASSERT_NOT_NULL(ext = oids_get_supported_extention(0));

    ASSERT_TRUE(pkix_check_oid_equal(exp_oid, ext) == true);

cleanup:

    ASN_FREE(&OBJECT_IDENTIFIER_desc, exp_oid);
}

static void test_oids_get_supported_extention_2(void)
{
    const OidNumbers *ext = NULL;
    int number_of_sup_ext = 26;

    ext = oids_get_supported_extention(number_of_sup_ext);
    ASSERT_TRUE(ext == NULL);
}

static void test_oids_get_oid_numbers_by_oid(void)
{
    OidNumbers *act_oid = NULL;
    OBJECT_IDENTIFIER_t *oid = NULL;
    char oid_str[] = "1.2.804.2.1.1.1";

    ASSERT_RET_OK(asn_create_oid_from_text(oid_str, &oid));
    ASSERT_NOT_NULL(act_oid = oids_get_oid_numbers_by_oid(oid));

    ASSERT_TRUE(pkix_check_oid_equal(oid, act_oid) == true);

cleanup:

    oids_oid_numbers_free(act_oid);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
}

static void test_oids_get_oid_numbers_by_str(void)
{
    OidNumbers *act_oid = NULL;
    OBJECT_IDENTIFIER_t *oid = NULL;
    char oid_str[] = "1.2.804.2.1.1.1.1";

    ASSERT_RET_OK(asn_create_oid_from_text(oid_str, &oid));
    ASSERT_NOT_NULL(act_oid = oids_get_oid_numbers_by_str(oid_str));

    ASSERT_TRUE(pkix_check_oid_equal(oid, act_oid) == true);

cleanup:

    oids_oid_numbers_free(act_oid);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
}

static void test_oids_get_oid_by_id(void)
{
    OBJECT_IDENTIFIER_t *act_oid = NULL;
    OBJECT_IDENTIFIER_t *exp_oid = NULL;
    char oid_str[] = "1.2.804.2.1.1.1.1.2";

    ASSERT_RET_OK(asn_create_oid_from_text(oid_str, &exp_oid));
    ASSERT_NOT_NULL(act_oid = oids_get_oid_by_id(OID_PKI_HASH_ID));

    ASSERT_EQUALS_ASN(&OBJECT_IDENTIFIER_desc, exp_oid, act_oid);

cleanup:

    ASN_FREE(&OBJECT_IDENTIFIER_desc, act_oid);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, exp_oid);
}

static void test_oids_get_oid_numbers_by_id(void)
{
    const OidNumbers *oid = NULL;

    oid = oids_get_oid_numbers_by_id(-1);
    ASSERT_TRUE(oid == NULL);
}

static void test_oids_get_oid_numbers_by_oid_2(void)
{
    OidNumbers *oids = NULL;
    OBJECT_IDENTIFIER_t *oid = NULL;

    oids = oids_get_oid_numbers_by_oid(oid);
    ASSERT_TRUE(oids == NULL);
}

static void test_oids_get_oid_numbers_by_str_2(void)
{
    OidNumbers *oids = NULL;
    char *oid_str = NULL;

    oids = oids_get_oid_numbers_by_str(oid_str);
    ASSERT_TRUE(oids == NULL);
}

void utest_oids(void)
{
    PR("%s\n", __FILE__);

    test_oids_get_supported_extention();
    test_oids_get_supported_extention_2();
    test_oids_get_oid_numbers_by_oid();
    test_oids_get_oid_numbers_by_str();
    test_oids_get_oid_by_id();
    test_oids_get_oid_numbers_by_id();
    test_oids_get_oid_numbers_by_oid_2();
    test_oids_get_oid_numbers_by_str_2();
}
