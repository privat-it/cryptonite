/*
 * Приклад: класичні хеш-функції — SHA-1, SHA-2, MD5, ГОСТ 34.311.
 *
 * Усі хеші бібліотеки мають однаковий життєвий цикл:
 * alloc → update → final → free.
 */

#include <stdio.h>

#include "byte_array.h"
#include "cryptonite_errors.h"
#include "gost34_311.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"

#define CHECK(func)                                                     \
    if ((ret = (func)) != RET_OK) {                                     \
        printf("Помилка %d у рядку %d\n", ret, __LINE__);               \
        goto cleanup;                                                   \
    }

int main(void)
{
    int ret = RET_OK;
    ByteArray *data = ba_alloc_from_str("Повідомлення для хешування");
    ByteArray *sync = NULL;
    ByteArray *hash = NULL;
    Sha1Ctx *sha1 = NULL;
    Sha2Ctx *sha2 = NULL;
    Md5Ctx *md5 = NULL;
    Gost34311Ctx *gost = NULL;

    /* SHA-1 */
    sha1 = sha1_alloc();
    CHECK(sha1_update(sha1, data));
    CHECK(sha1_final(sha1, &hash));
    printf("SHA-1      : ");
    ba_print(stdout, hash);
    ba_free(hash);
    hash = NULL;

    /* SHA-256 (варіанти: 224/256/384/512) */
    sha2 = sha2_alloc(SHA2_VARIANT_256);
    CHECK(sha2_update(sha2, data));
    CHECK(sha2_final(sha2, &hash));
    printf("SHA-256    : ");
    ba_print(stdout, hash);
    ba_free(hash);
    hash = NULL;

    /* MD5 (лише для сумісності зі старими системами!) */
    md5 = md5_alloc();
    CHECK(md5_update(md5, data));
    CHECK(md5_final(md5, &hash));
    printf("MD5        : ");
    ba_print(stdout, hash);
    ba_free(hash);
    hash = NULL;

    /* ГОСТ 34.311: контекст створюється з S-box та синхропосилкою (32 байти). */
    sync = ba_alloc_by_len(32);
    CHECK(ba_set(sync, 0x00));
    gost = gost34_311_alloc(GOST28147_SBOX_ID_1, sync);
    CHECK(gost34_311_update(gost, data));
    CHECK(gost34_311_final(gost, &hash));
    printf("ГОСТ 34.311: ");
    ba_print(stdout, hash);

cleanup:
    sha1_free(sha1);
    sha2_free(sha2);
    md5_free(md5);
    gost34_311_free(gost);
    ba_free(data);
    ba_free(sync);
    ba_free(hash);
    return (ret == RET_OK) ? 0 : 1;
}
