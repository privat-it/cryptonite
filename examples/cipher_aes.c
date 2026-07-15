/*
 * Приклад: AES у режимі CBC з доповненням PKCS#7.
 *
 * У CBC розмір даних має бути кратним блоку (16 байтів) —
 * для довільних даних застосовується доповнення з paddings.h.
 */

#include <stdio.h>

#include "aes.h"
#include "byte_array.h"
#include "cryptonite_errors.h"
#include "paddings.h"
#include "prng.h"

#define CHECK(func)                                                     \
    if ((ret = (func)) != RET_OK) {                                     \
        printf("Помилка %d у рядку %d\n", ret, __LINE__);               \
        goto cleanup;                                                   \
    }

int main(void)
{
    int ret = RET_OK;
    ByteArray *data = ba_alloc_from_str("Довільної довжини повідомлення для AES-CBC");
    ByteArray *seed = ba_alloc_by_len(40);
    ByteArray *key = NULL;
    ByteArray *iv = ba_alloc_by_len(16);
    ByteArray *padded = NULL;
    ByteArray *encrypted = NULL;
    ByteArray *decrypted = NULL;
    ByteArray *unpadded = NULL;
    PrngCtx *prng = NULL;
    AesCtx *ctx = NULL;

    /* УВАГА: seed константний лише для прикладу! */
    CHECK(ba_set(seed, 0x77));
    prng = prng_alloc(PRNG_MODE_DEFAULT, seed);
    CHECK(aes_generate_key(prng, 32, &key));   /* AES-256; можливі 16/24/32 */
    CHECK(ba_set(iv, 0x02));

    /* Доповнення PKCS#7 до кратності блоку. */
    CHECK(make_pkcs7_padding(data, 16, &padded));

    ctx = aes_alloc();
    CHECK(aes_init_cbc(ctx, key, iv));
    CHECK(aes_encrypt(ctx, padded, &encrypted));

    CHECK(aes_init_cbc(ctx, key, iv));
    CHECK(aes_decrypt(ctx, encrypted, &decrypted));

    /* Зняття доповнення. */
    CHECK(make_pkcs7_unpadding(decrypted, &unpadded));

    printf("AES-256-CBC: розшифровано %s (довжина %u -> %u -> %u байтів)\n",
           ba_cmp(data, unpadded) == 0 ? "коректно" : "З ПОМИЛКОЮ",
           (unsigned)ba_get_len(data), (unsigned)ba_get_len(padded),
           (unsigned)ba_get_len(unpadded));

cleanup:
    aes_free(ctx);
    prng_free(prng);
    ba_free(data);
    ba_free(seed);
    ba_free_private(key);
    ba_free(iv);
    ba_free(padded);
    ba_free(encrypted);
    ba_free(decrypted);
    ba_free(unpadded);
    return (ret == RET_OK) ? 0 : 1;
}
