#include "iitkey.h"
#include "test_utils.h"
#include "aid.h"
#include "cryptonite_manager.h"
#include "storage_errors.h"

void test_key6_load(IITStorageCtx **storage)
{
    ByteArray *storage_body = NULL;
    const char *storage_path = "src/storageUtest/resources/Key-6.dat";
    const char *storage_pass = "tectfom";
    SignAdapter *sa = NULL;
    DhAdapter *dha = NULL;

    ASSERT_RET_OK(ba_alloc_from_file(storage_path, &storage_body));

    ASSERT_RET_OK(ittkey_decode(storage_path, storage_body, storage_pass, storage));

    ASSERT_RET_OK(iitkey_get_dh_adapter(*storage, &dha));

    ASSERT_RET_OK(iitkey_get_sign_adapter(*storage, &sa));


cleanup:
    sign_adapter_free(sa);
    dh_adapter_free(dha);
    BA_FREE(storage_body);
}

void utest_key6(void)
{
    IITStorageCtx *storage = NULL;

    PR("%s\n", __FILE__);

    test_key6_load(&storage);
    ASSERT_NOT_NULL(storage);

cleanup:

    iitkey_free(storage);

}
