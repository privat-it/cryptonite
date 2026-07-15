/*
 * Приклад: електронний підпис за ДСТУ 4145-2002.
 *
 * Генерація ключової пари, підписання хешу повідомлення («Купина»),
 * перевірка підпису та демонстрація виявлення підробки.
 */

#include <stdio.h>

#include "byte_array.h"
#include "cryptonite_errors.h"
#include "dstu4145.h"
#include "dstu7564.h"
#include "prng.h"

#define CHECK(func)                                                     \
    if ((ret = (func)) != RET_OK) {                                     \
        printf("Помилка %d у рядку %d\n", ret, __LINE__);               \
        goto cleanup;                                                   \
    }

int main(void)
{
    int ret = RET_OK;
    ByteArray *data = ba_alloc_from_str("Документ, який підписуємо");
    ByteArray *seed = ba_alloc_by_len(40);
    ByteArray *hash = NULL;
    ByteArray *priv = NULL;
    ByteArray *qx = NULL, *qy = NULL;
    ByteArray *r = NULL, *s = NULL;
    PrngCtx *prng = NULL;
    Dstu7564Ctx *hash_ctx = NULL;
    Dstu4145Ctx *ctx = NULL;

    /* 1. Хеш повідомлення (Купина-256). */
    hash_ctx = dstu7564_alloc(DSTU7564_SBOX_1);
    CHECK(dstu7564_init(hash_ctx, 32));
    CHECK(dstu7564_update(hash_ctx, data));
    CHECK(dstu7564_final(hash_ctx, &hash));

    /* 2. ГПВЧ для ДСТУ 4145 — обов'язково PRNG_MODE_DSTU.
       УВАГА: seed константний лише для прикладу! */
    CHECK(ba_set(seed, 0xba));
    prng = prng_alloc(PRNG_MODE_DSTU, seed);

    /* 3. Контекст зі стандартними параметрами кривої M257 (поліноміальний базис). */
    ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);

    /* 4. Ключова пара. */
    CHECK(dstu4145_generate_privkey(ctx, prng, &priv));
    CHECK(dstu4145_get_pubkey(ctx, priv, &qx, &qy));

    /* 5. Підписання. */
    CHECK(dstu4145_init_sign(ctx, priv, prng));
    CHECK(dstu4145_sign(ctx, hash, &r, &s));
    printf("Підпис створено (r,s по %u байтів)\n", (unsigned)ba_get_len(r));

    /* 6. Перевірка. */
    CHECK(dstu4145_init_verify(ctx, qx, qy));
    CHECK(dstu4145_verify(ctx, hash, r, s));
    printf("Підпис коректний\n");

    /* 7. Підробка: змінюємо один байт хешу — перевірка має провалитись. */
    {
        ByteArray *tampered = ba_copy_with_alloc(hash, 0, 0);
        ba_xor(tampered, r);   /* псуємо хеш */
        if (dstu4145_verify(ctx, tampered, r, s) != RET_OK) {
            printf("Підроблені дані виявлено (verify != RET_OK)\n");
        } else {
            printf("ПОМИЛКА: підробку не виявлено!\n");
            ret = -1;
        }
        ba_free(tampered);
    }

cleanup:
    dstu4145_free(ctx);
    dstu7564_free(hash_ctx);
    prng_free(prng);
    ba_free(data);
    ba_free(seed);
    ba_free(hash);
    ba_free_private(priv);
    ba_free(qx);
    ba_free(qy);
    ba_free(r);
    ba_free(s);
    return (ret == RET_OK) ? 0 : 1;
}
