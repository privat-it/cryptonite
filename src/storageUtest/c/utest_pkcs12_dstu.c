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
    bool is_generated;
    ByteArray *cert = NULL;

    ASSERT_RET_OK(pkcs12_create(KS_FILE_PKCS12_WITH_GOST34311, password, rounds, &store));

    ASSERT_RET_OK(pkcs12_is_key_generated(store, &is_generated));
    ASSERT_TRUE(is_generated == false);
    ASSERT_RET(RET_STORAGE_NO_KEY, pkcs12_select_key(store, NULL, NULL));
    ASSERT_RET(RET_STORAGE_NO_KEY, pkcs12_store_key(store, NULL, NULL, rounds));

    ASSERT_RET(RET_STORAGE_KEY_NOT_SELECTED, pkcs12_get_certificate(store, 0, &cert));
    ASSERT_TRUE(cert == NULL);

    ASSERT_RET_OK(pkcs12_encode(store, &storage_ba));

    *storage = store;

cleanup:

    BA_FREE(storage_ba, cert);
}

static void test_pkcs12_generate_keys(Pkcs12Ctx *storage)
{
    int rounds = 1024;
    const char *password = "123456";

    ASSERT_RET_OK(pkcs12_generate_key(storage, NULL));
    ASSERT_RET_OK(pkcs12_store_key(storage, "key1", password, rounds));

    ASSERT_RET_OK(pkcs12_generate_key(storage, NULL));
    ASSERT_RET_OK(pkcs12_store_key(storage, "key2", password, rounds));

cleanup:

    return;
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

static void test_get_dh_adapter(Pkcs12Ctx *storage, DhAdapter **dha)
{
    const Pkcs12Keypair *keys = NULL;
    size_t cnt = 0;

    ASSERT_NOT_NULL(dha);

    ASSERT_RET_OK(pkcs12_enum_keys(storage, &keys, &cnt));
    ASSERT_TRUE(cnt > 0);
    ASSERT_RET_OK(pkcs12_select_key(storage, NULL, NULL));
    ASSERT_RET_OK(pkcs12_get_dh_adapter(storage, dha));
cleanup:

    return;
}

static void test_get_dh_adapter_key_not_selected(Pkcs12Ctx *storage)
{
    DhAdapter *dha = NULL;

    ASSERT_RET(RET_STORAGE_KEY_NOT_SELECTED, pkcs12_get_dh_adapter(storage, &dha));
    ASSERT_TRUE(dha == NULL);

cleanup:

    dh_adapter_free(dha);
}

static void test_get_verify_adapter_key_not_selected(Pkcs12Ctx *storage)
{
    VerifyAdapter *va = NULL;

    ASSERT_RET(RET_STORAGE_KEY_NOT_SELECTED, pkcs12_get_verify_adapter(storage, &va));
    ASSERT_TRUE(va == NULL);

cleanup:

    verify_adapter_free(va);
}

static void test_get_sign_adapter_key_not_selected(Pkcs12Ctx *storage)
{
    SignAdapter *sa = NULL;

    ASSERT_RET(RET_STORAGE_KEY_NOT_SELECTED, pkcs12_get_sign_adapter(storage, &sa));
    ASSERT_TRUE(sa == NULL);

cleanup:

    sign_adapter_free(sa);
}

static void test_pkcs12_decode_rsa(void)
{
    Pkcs12Ctx *storage = NULL;
    ByteArray *storage_body = NULL;
    const char *storage_path = "src/storageUtest/resources/pkcs12_rsa(123456).pfx";
    const char *storage_pass = "123456";

    ASSERT_RET_OK(ba_alloc_from_file(storage_path, &storage_body));
    ASSERT_RET(RET_STORAGE_UNSUPPORTED_CONTENT_ENC_ALG, pkcs12_decode(storage_path, storage_body, storage_pass, &storage));
    ASSERT_TRUE(storage == NULL);

cleanup:

    ba_free(storage_body);
    pkcs12_free(storage);
}

static void test_pkcs12_decode_unsup_cinfo_type(void)
{
    Pkcs12Ctx *storage = NULL;
    ByteArray *storage_body = ba_alloc_from_le_hex_string("308204AC020100308204A506092A864886F70D010702A082049630820492020103310B300906052B0E03021A0500306A060B2A864886F70D0109100104A05B0459305702010106022901301F300706052B0E03021A0414B6C511873B07A73513161B142D344B7B845CACEF02047F020304181332303136303732303133323130362E3737375A300902010180010181010A0101FF02047F020304A08202C6308202C2308201ACA003020102020101300B06092A864886F70D010105301E311C3009060355040613025255300F06035504031E080054006500730074301E170D3133303133313232303030305A170D3136303133313232303030305A301E311C3009060355040613025255300F06035504031E08005400650073007430820122300D06092A864886F70D01010105000382010F003082010A0282010100DFC7CB945173DBD0CC287584B634E7FF2B211759B3670554F0EF932EA688520526110344CC5579568BD4EC9D409F99FCC773505E99D7B289A1CA2D930C3E1DC9D20771B741DF253A4F3DC4D7DA676B56779738CB4BDF440AB9BFC46F4FFB81C91C7DF5C166B3038BCF2153D479911464F365DDE75A0FCC7B33110D2D289BE122A03BD6E6562FBA03D244A6DADB1A4DCD47711775C0193526E0097C50D2C36653DEB41420117A23294D6D0F4628B743D916774760FF35F97E800CA9DDF4A0A88F71D2AD996E2B8EAA053982AD19CF4AC5D61C2833BA23EFFEEADBA4437C07DF11FEF735282ADFEBDA8EC228FF3A266B04BD6F4F13D5C00E0A0A319A29FF3F1EA30203010001A30F300D300B0603551D0F040403020002300B06092A864886F70D0101050382010100027AACA4A58B18E48F899FC43C610F84DBE5A151187046B300F1156FAF9291B3A7B8F981CE2BAA1DC69C3EEC377CAE5132BA66E4F612EE7CDCABE83B710712AC23ECD93BDF6B6E0E66ABAEA704556D6DC7578822D8EEA397553E9EE8B4F73199839AC8EDF6101ECF9CEE24C1933FCC650806CD166427B05713361F1F56C7F4045BF64B232CA76B177EA53A78B976D980406F33694D9051E66BB8F081CC51AF1584E8365F1865E5DF9118D0798626C41B5D6F41ED47F24CC993F376C1A811B142AEBED3B0A832ECB81FAC18FC261D4293B5D46078B25622BF783027484D7C82D807E76E9CB87DB67D7C858341BB0E3E2659FB8CCE65A46B08EF92F3D4E51C169131820148308201440201013023301E311C3009060355040613025255300F06035504031E080054006500730074020101300906052B0E03021A0500300B06092A864886F70D01010504820100B842BA861AA9B274D865A2934A9403048EB7E7B54932D06C0F9C0B2E452D6630E3431D5DE3E9E7582B2A2D41333D99391F13D6AD753FB7CD41E34546941E21D3671A84F1DD534262903368E372B48607029B2C3C38DDD878459A89D850410521494B29C30ADDED6367A78FBD5C24EC2EB86EB6EE9058A4D9296DFD316F0282C093524B25B8A4E40E4291D201E1894D1E50CFF60AFDDB3E2D5FDA8398A23E693C4573EFCFEFB58247EB300577F1A2FEC3FBCB3898FE44F982AB68DFF276FD174516FBB992F6DDE391AFBCC6AD7766C7DC8967950E597E569EA6E73DEABF923216752B991F52BB5135702F8C29C89FA1DDED2D55063CA28F125C4CAD1890FC3BE8");
    const char *storage_pass = "123456";

    //тип cinfo - signedData
    ASSERT_RET(RET_PKIX_CINFO_NOT_DATA, pkcs12_decode(NULL, storage_body, storage_pass, &storage));
    ASSERT_TRUE(storage == NULL);

cleanup:

    ba_free(storage_body);
    pkcs12_free(storage);
}

static void test_pkcs12_decode_mac_verify_error(void)
{
    Pkcs12Ctx *storage = NULL;
    ByteArray *storage_body = ba_alloc_from_le_hex_string("3082043E020103308203DB06092A864886F70D010701A08203CC048203C8308203C43082026706092A864886F70D010706A0820258308202540201003082024D06092A864886F70D010701301C060A2A864886F70D010C0106300E040857F1061CE69A72A8020208008082022019FE984270D41E0C821932A7407DB98DB1D44AB1ED485F042236E98C9E06716BB23D6F3527E96EC9E2F57689C3AF68B2F0CFFD60201DA3D8781ABEA20065103A7C5029EB30A745C6CB524B7136B840DB4C3D037059C1666D9790B2321594B5FDC0BAA3DE6C09945882BFA24EAA6D59D951A5770A982F49FB5BE5776C224552D559D15F48B5E7351DF3EF24CE7AD07FF6F9C3E659A1A8826989C649594475987D36C9D9D5EC290C3D166AA4CD30B3582EEA4936552F02D182F69034031AB642495697C8167670570B4B7B8ED4785D514F8F8C7E197EABE949EB6D42FC6C7B2C7EDC29DAFA49F27DE600E8189050859C626AECAE66C043F33B2D1FEC16089EAD998F2155279E23410C3A6ED674D9A8438088A4BD43AD1009EB998113B738088ACDD1B83A7BCDE7C33696C4A76CF427CDBD6E7E6817E405E15654B75324E9091262432BCFDFE25783E59B4E4DE17E9AB5B4B15EFFBFC70B7CD9C42CC7552B1CB302FFA3461BED508585F26A27598FC1B706C4CFE007B3125D7588642807638B7494718B5B3A5F34A518703DA0DBF572F6045F27109832FEAAD10775C1EA8FE01F2ADBAC4242DE1BEBBBD479B042FC1D5E4E01DEAAD5C547455553FF9F5B71170B16E88E7A2204CC9D2E056060CA905AD339E8AD466B6BDCAB9C63B12CF28D40A80818E7EDA9E280A851B8EB9A92EFA355FCFE7D1F0AB830F269AE30B796BB68A753EF85B9525EF75075ED5CFF42B33AB6E8B2278BC4E5A1FCE9D7C72EF15EA21FDD3082015506092A864886F70D010701A0820146048201423082013E3082013A060B2A864886F70D010C0A0102A081E43081E1301C060A2A864886F70D010C0103300E0408D52D28086B00ED9F020208000481C01557781EB7CE563BE2A2FF8262AB5F5E8D638B7300AA21F6DCA89F863917ACC3ACEFC175CDD83D3D4352DDEB28DEF05401BB800E5FF17675F2BAB1C0520A90CECA714D80FE7F6E4AED4FC268303F930C5856CA248D9F145DAB95635B5C6E5EBB6CB1439E6E493D479DF43E2597C180775EB91AA52E00FEB4CB9C01C4B6F7A7E662FE7FBF497C9E9966B9DB6D849D02F22733AB63E0D5A75A4D718795F839BAB32928F59353FBCC84A420AB2DDD0628A093721474E7D5D27CF676AAD19D3BAFEE3144301D06092A864886F70D01091431101E0E006D0079005F006E0061006D0065302306092A864886F70D01091531160414B7617BBF74385D859FEE148C52BA385C3BBE22AA305A3032300E060A2A86240201010101020105000420AA930979B25F6F1DFFD264DEC55588729E1AE6D34D36B407B6FEA78B6321350A04209FAFF3EC3945578F747BFD909FFF22E6DB53E0A384D9979B89075F6CC419C2B502022710");
    const char *storage_pass = "123456";

    ASSERT_RET(RET_STORAGE_MAC_VERIFY_ERROR, pkcs12_decode(NULL, storage_body, storage_pass, &storage));
    ASSERT_TRUE(storage == NULL);

cleanup:

    ba_free(storage_body);
    pkcs12_free(storage);
}

void utest_pkcs12_dstu(void)
{
    Pkcs12Ctx *storage = NULL;
    SignAdapter *sa = NULL;
    VerifyAdapter *va = NULL;
    DhAdapter *dha = NULL;

    PR("%s\n", __FILE__);

    test_pkcs12_load_iit(&storage);
    ASSERT_NOT_NULL(storage);

    test_get_keys(storage);
    test_pkcs12_set_certificates(storage);
    test_get_dh_adapter_key_not_selected(storage);
    test_get_verify_adapter_key_not_selected(storage);
    test_get_sign_adapter_key_not_selected(storage);

    test_get_sign_adapter(storage, &sa);
    test_get_verify_adapter(storage, &va);
    test_sign_verify(sa, va);
    test_get_dh_adapter(storage, &dha);

    pkcs12_free(storage);
    storage = NULL;
    sign_adapter_free(sa);
    sa = NULL;
    verify_adapter_free(va);
    va = NULL;
    dh_adapter_free(dha);
    dha = NULL;

    test_pkcs12_generate(&storage);
    ASSERT_NOT_NULL(storage);

    test_pkcs12_set_certificates(storage);
    test_pkcs12_generate_keys(storage);
    test_get_keys(storage);
    test_get_sign_adapter(storage, &sa);
    test_get_verify_adapter(storage, &va);
    test_sign_verify(sa, va);
    test_get_dh_adapter(storage, &dha);

    test_pkcs12_iit_storage();

    test_pkcs12_decode_rsa();
    test_pkcs12_decode_unsup_cinfo_type();
    test_pkcs12_decode_mac_verify_error();

cleanup:

    verify_adapter_free(va);
    sign_adapter_free(sa);
    pkcs12_free(storage);
}
