/*
 * Приклад: шифрування за ДСТУ 7624:2014 («Калина»).
 *
 * - режим CTR (потоковий, довільна довжина даних);
 * - режим GCM (автентифіковане шифрування: шифротекст + MAC).
 */

#include <stdio.h>

#include "byte_array.h"
#include "cryptonite_errors.h"
#include "dstu7624.h"
#include "prng.h"

#define CHECK(func)                                                     \
    if ((ret = (func)) != RET_OK) {                                     \
        printf("Помилка %d у рядку %d\n", ret, __LINE__);               \
        goto cleanup;                                                   \
    }

int main(void)
{
    int ret = RET_OK;
    size_t block_len = 16;   /* Калина-128; можливі 16/32/64 */
    ByteArray *data = ba_alloc_from_str("Таємне повідомлення для шифрування «Калиною»");
    ByteArray *auth_data = ba_alloc_from_str("відкриті, але автентифіковані дані");
    ByteArray *seed = ba_alloc_by_len(40);
    ByteArray *key = NULL;
    ByteArray *iv = NULL;
    ByteArray *encrypted = NULL;
    ByteArray *decrypted = NULL;
    ByteArray *mac = NULL;
    PrngCtx *prng = NULL;
    Dstu7624Ctx *ctx = NULL;

    /* УВАГА: seed константний лише для прикладу — використовуйте справжню ентропію! */
    CHECK(ba_set(seed, 0xa5));
    prng = prng_alloc(PRNG_MODE_DEFAULT, seed);

    CHECK(dstu7624_generate_key(prng, 16, &key));   /* ключ 16/32/64 байти */
    iv = ba_alloc_by_len(block_len);                /* IV = розмір блока */
    CHECK(ba_set(iv, 0x01));                        /* IV не повинен повторюватись! */

    ctx = dstu7624_alloc(DSTU7624_SBOX_1);

    /* --- Режим CTR --- */
    CHECK(dstu7624_init_ctr(ctx, key, iv));
    CHECK(dstu7624_encrypt(ctx, data, &encrypted));

    CHECK(dstu7624_init_ctr(ctx, key, iv));         /* повторний init перед decrypt */
    CHECK(dstu7624_decrypt(ctx, encrypted, &decrypted));

    printf("CTR: розшифровано %s\n",
           ba_cmp(data, decrypted) == 0 ? "коректно" : "З ПОМИЛКОЮ");
    ba_free(encrypted);
    ba_free(decrypted);
    encrypted = NULL;
    decrypted = NULL;

    /* --- Режим GCM (AEAD) --- */
    CHECK(dstu7624_init_gcm(ctx, key, iv, block_len));
    CHECK(dstu7624_encrypt_mac(ctx, auth_data, data, &mac, &encrypted));

    CHECK(dstu7624_init_gcm(ctx, key, iv, block_len));
    /* decrypt_mac поверне помилку, якщо шифротекст або auth_data підроблено */
    CHECK(dstu7624_decrypt_mac(ctx, auth_data, encrypted, mac, &decrypted));

    printf("GCM: розшифровано %s, MAC перевірено\n",
           ba_cmp(data, decrypted) == 0 ? "коректно" : "З ПОМИЛКОЮ");

cleanup:
    dstu7624_free(ctx);
    prng_free(prng);
    ba_free(data);
    ba_free(auth_data);
    ba_free(seed);
    ba_free_private(key);
    ba_free(iv);
    ba_free(encrypted);
    ba_free(decrypted);
    ba_free(mac);
    return (ret == RET_OK) ? 0 : 1;
}
