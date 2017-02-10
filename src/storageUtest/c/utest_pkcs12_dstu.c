/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "test_utils.h"
#include "aid.h"
#include "pkcs12.h"
#include "cryptonite_manager.h"
#include "storage_errors.h"

void test_pkcs12_load_iit(Pkcs12Ctx **storage)
{
    ByteArray *storage_body = NULL;
    const char *storage_path = "src/storageUtest/resources/pkcs12_by_iit(123456).pfx";
    const char *storage_pass = "123456";
    const char *actual;

    ASSERT_RET_OK(ba_alloc_from_file(storage_path, &storage_body));

    ASSERT_RET_OK(pkcs12_decode(storage_path, storage_body, storage_pass, storage));

    ASSERT_RET_OK(pkcs12_get_storage_name(*storage, &actual));
    ASSERT_EQUALS_STR(storage_path, actual);

cleanup:

    BA_FREE(storage_body);
}

static void test_pkcs12_generate(Pkcs12Ctx **storage)
{
    Pkcs12Ctx *store = NULL;
    char *password = "123456";
    ByteArray *storage_ba = NULL;
    int rounds = 1024;

    ASSERT_RET_OK(pkcs12_create(KS_FILE_PKCS12_WITH_GOST34311, password, rounds, &store));
    ASSERT_RET_OK(pkcs12_generate_key(store, NULL));
    ASSERT_RET_OK(pkcs12_store_key(store, "alias", NULL, 1024));
    ASSERT_RET_OK(pkcs12_encode(store, &storage_ba));

    *storage = store;

cleanup:

    BA_FREE(storage_ba);
}

static void test_get_keys(Pkcs12Ctx *storage)
{
    size_t i;
    const Pkcs12Keypair *keys = NULL;
    size_t cnt = 0;

    char *expected[] = {"key1", "key2"};

    ASSERT_RET_OK(pkcs12_enum_keys(storage, &keys, &cnt));

    ASSERT_TRUE(cnt == 2);

    for (i = 0; i < cnt; i++) {
        ASSERT_EQUALS_STR(expected[i], keys[i].alias);
    }

cleanup:

    return;
}

static void test_pkcs12_set_certificates(Pkcs12Ctx *storage)
{
    const ByteArray *certs[2] = {NULL, NULL};
    ByteArray *cert = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/storageUtest/resources/pkcs8.crt", &cert));

    certs[0] = cert;

    ASSERT_RET_OK(pkcs12_set_certificates(storage, certs));

cleanup:

    BA_FREE(cert);
}

static void test_get_sign_adapter(Pkcs12Ctx *storage, SignAdapter **sa)
{
    const Pkcs12Keypair *keys = NULL;
    size_t cnt = 0;

    ASSERT_NOT_NULL(sa);

    ASSERT_RET_OK(pkcs12_enum_keys(storage, &keys, &cnt));
    ASSERT_TRUE(cnt > 0);
    ASSERT_RET_OK(pkcs12_select_key(storage, keys[0].alias, NULL));
    ASSERT_RET_OK(pkcs12_get_sign_adapter(storage, sa));

cleanup:

    return;
}

static void test_get_verify_adapter(Pkcs12Ctx *storage, VerifyAdapter **va)
{
    const Pkcs12Keypair *keys = NULL;
    size_t cnt = 0;

    ASSERT_NOT_NULL(va);

    ASSERT_RET_OK(pkcs12_enum_keys(storage, &keys, &cnt));
    ASSERT_TRUE(cnt > 0);
    ASSERT_RET_OK(pkcs12_select_key(storage, keys[0].alias, NULL));
    ASSERT_RET_OK(pkcs12_get_verify_adapter(storage, va));
cleanup:

    return;
}

static void test_sign_verify(SignAdapter *sa, VerifyAdapter *va)
{
    ByteArray *sign = NULL;
    ByteArray *data = ba_alloc_by_len(99);

    ASSERT_RET_OK(ba_set(data, 0x49));

    ASSERT_RET_OK(sa->sign_data(sa, data, &sign));
    ASSERT_RET_OK(va->verify_data(va, data, sign));

cleanup:

    BA_FREE(sign, data);
}

static void test_pkcs12_iit_storage(void)
{
    ByteArray *storage_ba = NULL;
    ByteArray *encoded_storage = NULL;
    char password[] = "123456";
    Pkcs12Ctx *st = NULL;
    const Pkcs12Keypair *keys = NULL;
    size_t cnt = 0;
    ByteArray **ba = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/storageUtest/resources/pkcs12_by_iit(123456).pfx", &storage_ba));

    ASSERT_RET_OK(pkcs12_decode(NULL, storage_ba, password, &st));
    ASSERT_RET_OK(pkcs12_enum_keys(st, &keys, &cnt));

    pkcs12_get_certificates(st, &ba);
    ASSERT_EQUALS_SIZE_T(2, cnt);
    ASSERT_EQUALS_STR("key1", keys[0].alias);
    ASSERT_EQUALS_STR("key2", keys[1].alias);

    ASSERT_RET_OK(pkcs12_select_key(st, "key1", password));
    ASSERT_RET_OK(pkcs12_encode(st, &encoded_storage));

    ASSERT_EQUALS_BA(storage_ba, encoded_storage);

cleanup:

    BA_FREE(storage_ba, encoded_storage, ba);
    pkcs12_free(st);
}

void utest_pkcs12_dstu(void)
{
    Pkcs12Ctx *storage = NULL;
    SignAdapter *sa = NULL;
    VerifyAdapter *va = NULL;

    PR("%s\n", __FILE__);

    test_pkcs12_load_iit(&storage);
    ASSERT_NOT_NULL(storage);

    test_get_keys(storage);
    test_pkcs12_set_certificates(storage);

    test_get_sign_adapter(storage, &sa);
    test_get_verify_adapter(storage, &va);
    test_sign_verify(sa, va);

    pkcs12_free(storage);
    storage = NULL;
    sign_adapter_free(sa);
    sa = NULL;
    verify_adapter_free(va);
    va = NULL;

    test_pkcs12_generate(&storage);
    ASSERT_NOT_NULL(storage);

    test_get_sign_adapter(storage, &sa);
    test_get_verify_adapter(storage, &va);
    test_sign_verify(sa, va);

    test_pkcs12_iit_storage();

cleanup:

    verify_adapter_free(va);
    sign_adapter_free(sa);
    pkcs12_free(storage);
}
