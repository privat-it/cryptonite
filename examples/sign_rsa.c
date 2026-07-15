/*
 * Приклад: підпис RSA за схемою PKCS#1 v1.5.
 *
 * Розмір модуля 2048 біт узято для швидкості прикладу;
 * для нового коду рекомендується >= 3072.
 */

#include <stdio.h>

#include "byte_array.h"
#include "cryptonite_errors.h"
#include "prng.h"
#include "rsa.h"
#include "sha2.h"

#define CHECK(func)                                                     \
    if ((ret = (func)) != RET_OK) {                                     \
        printf("Помилка %d у рядку %d\n", ret, __LINE__);               \
        goto cleanup;                                                   \
    }

int main(void)
{
    int ret = RET_OK;
    uint8_t e_bytes[] = { 0x01, 0x00, 0x01 };            /* e = 65537 */
    ByteArray *data = ba_alloc_from_str("Документ для підпису RSA");
    ByteArray *e = ba_alloc_from_uint8(e_bytes, sizeof(e_bytes));
    ByteArray *seed = ba_alloc_by_len(40);
    ByteArray *hash = NULL;
    ByteArray *n = NULL;
    ByteArray *priv = NULL;
    ByteArray *sign = NULL;
    PrngCtx *prng = NULL;
    Sha2Ctx *sha = NULL;
    RsaCtx *ctx = NULL;

    sha = sha2_alloc(SHA2_VARIANT_256);
    CHECK(sha2_update(sha, data));
    CHECK(sha2_final(sha, &hash));

    /* УВАГА: seed константний лише для прикладу! */
    CHECK(ba_set(seed, 0x9e));
    prng = prng_alloc(PRNG_MODE_DEFAULT, seed);

    ctx = rsa_alloc();
    printf("Генерація ключа RSA-2048 (може тривати кілька секунд)...\n");
    CHECK(rsa_generate_privkey(ctx, prng, 2048, e, &n, &priv));

    CHECK(rsa_init_sign_pkcs1_v1_5(ctx, RSA_HASH_SHA256, n, priv));
    CHECK(rsa_sign_pkcs1_v1_5(ctx, hash, &sign));
    printf("Підпис створено (%u байтів)\n", (unsigned)ba_get_len(sign));

    CHECK(rsa_init_verify_pkcs1_v1_5(ctx, RSA_HASH_SHA256, n, e));
    CHECK(rsa_verify_pkcs1_v1_5(ctx, hash, sign));
    printf("Підпис коректний\n");

cleanup:
    rsa_free(ctx);
    sha2_free(sha);
    prng_free(prng);
    ba_free(data);
    ba_free(e);
    ba_free(seed);
    ba_free(hash);
    ba_free(n);
    ba_free_private(priv);
    ba_free(sign);
    return (ret == RET_OK) ? 0 : 1;
}
