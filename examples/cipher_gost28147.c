/*
 * Приклад: шифрування за ДСТУ ГОСТ 28147:2009 («Магма»).
 *
 * Режим гамування (CTR) та імітовставка (MAC).
 */

#include <stdio.h>

#include "byte_array.h"
#include "cryptonite_errors.h"
#include "gost28147.h"
#include "prng.h"

#define CHECK(func)                                                     \
    if ((ret = (func)) != RET_OK) {                                     \
        printf("Помилка %d у рядку %d\n", ret, __LINE__);               \
        goto cleanup;                                                   \
    }

int main(void)
{
    int ret = RET_OK;
    ByteArray *data = ba_alloc_from_str("Повідомлення для ГОСТ 28147-89");
    ByteArray *seed = ba_alloc_by_len(40);
    ByteArray *key = NULL;
    ByteArray *iv = ba_alloc_by_len(8);     /* IV (синхропосилка) — 8 байтів */
    ByteArray *encrypted = NULL;
    ByteArray *decrypted = NULL;
    ByteArray *mac = NULL;
    PrngCtx *prng = NULL;
    Gost28147Ctx *ctx = NULL;

    /* УВАГА: seed константний лише для прикладу! */
    CHECK(ba_set(seed, 0x5a));
    prng = prng_alloc(PRNG_MODE_DEFAULT, seed);
    CHECK(gost28147_generate_key(prng, &key));    /* ключ 32 байти */
    CHECK(ba_set(iv, 0x01));

    ctx = gost28147_alloc(GOST28147_SBOX_ID_1);   /* 18 стандартних таблиць замін */

    /* --- Гамування (CTR) --- */
    CHECK(gost28147_init_ctr(ctx, key, iv));
    CHECK(gost28147_encrypt(ctx, data, &encrypted));

    CHECK(gost28147_init_ctr(ctx, key, iv));
    CHECK(gost28147_decrypt(ctx, encrypted, &decrypted));

    printf("CTR: розшифровано %s\n",
           ba_cmp(data, decrypted) == 0 ? "коректно" : "З ПОМИЛКОЮ");

    /* --- Імітовставка --- */
    CHECK(gost28147_init_mac(ctx, key));
    CHECK(gost28147_update_mac(ctx, data));
    CHECK(gost28147_final_mac(ctx, &mac));
    printf("Імітовставка: ");
    ba_print(stdout, mac);

cleanup:
    gost28147_free(ctx);
    prng_free(prng);
    ba_free(data);
    ba_free(seed);
    ba_free_private(key);
    ba_free(iv);
    ba_free(encrypted);
    ba_free(decrypted);
    ba_free(mac);
    return (ret == RET_OK) ? 0 : 1;
}
