/*
 * Приклад: коди автентифікації повідомлень (MAC).
 *
 * - HMAC на базі SHA-256;
 * - KMAC на базі «Купини» (ДСТУ 7564);
 * - CMAC на базі «Калини» (ДСТУ 7624).
 */

#include <stdio.h>

#include "byte_array.h"
#include "cryptonite_errors.h"
#include "dstu7564.h"
#include "dstu7624.h"
#include "hmac.h"
#include "sha2.h"

#define CHECK(func)                                                     \
    if ((ret = (func)) != RET_OK) {                                     \
        printf("Помилка %d у рядку %d\n", ret, __LINE__);               \
        goto cleanup;                                                   \
    }

int main(void)
{
    int ret = RET_OK;
    ByteArray *data = ba_alloc_from_str("Дані, цілісність яких захищаємо");
    ByteArray *key = ba_alloc_by_len(32);
    ByteArray *mac = NULL;
    HmacCtx *hmac = NULL;
    Dstu7564Ctx *kupyna = NULL;
    Dstu7624Ctx *kalyna = NULL;

    CHECK(ba_set(key, 0x35));   /* у реальному коді — випадковий секретний ключ */

    /* HMAC-SHA256 */
    hmac = hmac_alloc_sha2(SHA2_VARIANT_256);
    CHECK(hmac_init(hmac, key));
    CHECK(hmac_update(hmac, data));
    CHECK(hmac_final(hmac, &mac));
    printf("HMAC-SHA256 : ");
    ba_print(stdout, mac);
    ba_free(mac);
    mac = NULL;

    /* KMAC на «Купині»: власний механізм ДСТУ 7564 (init_kmac/update_kmac/final_kmac). */
    kupyna = dstu7564_alloc(DSTU7564_SBOX_1);
    CHECK(dstu7564_init_kmac(kupyna, key, 32));   /* довжина MAC у байтах */
    CHECK(dstu7564_update_kmac(kupyna, data));
    CHECK(dstu7564_final_kmac(kupyna, &mac));
    printf("KMAC-Купина : ");
    ba_print(stdout, mac);
    ba_free(mac);
    mac = NULL;

    /* CMAC на «Калині»: блок 16 байтів, MAC 16 байтів. */
    kalyna = dstu7624_alloc(DSTU7624_SBOX_1);
    CHECK(dstu7624_init_cmac(kalyna, key, 16, 16));
    CHECK(dstu7624_update_mac(kalyna, data));
    CHECK(dstu7624_final_mac(kalyna, &mac));
    printf("CMAC-Калина : ");
    ba_print(stdout, mac);

cleanup:
    hmac_free(hmac);
    dstu7564_free(kupyna);
    dstu7624_free(kalyna);
    ba_free(data);
    ba_free_private(key);   /* секрети — через ba_free_private (обнуляє пам'ять) */
    ba_free(mac);
    return (ret == RET_OK) ? 0 : 1;
}
