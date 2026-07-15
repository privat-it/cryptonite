/*
 * Приклад: ключове сховище PKCS#12.
 *
 * Створення сховища, генерація ключової пари ДСТУ 4145 усередині нього,
 * серіалізація у байти, повторне відкриття за паролем.
 */

#include <stdio.h>

#include "aid.h"
#include "byte_array.h"
#include "cryptonite_errors.h"
#include "dstu4145.h"
#include "gost28147.h"
#include "pkcs12.h"

#define STORAGE_PASSWORD "storage-password"
#define KEY_PASSWORD     "key-password"
#define ROUNDS           1024

#define CHECK(func)                                                     \
    if ((ret = (func)) != RET_OK) {                                     \
        printf("Помилка %d у рядку %d\n", ret, __LINE__);               \
        goto cleanup;                                                   \
    }

int main(void)
{
    int ret = RET_OK;
    Dstu4145Ctx *ec_params = NULL;
    Gost28147Ctx *cipher_params = NULL;
    AlgorithmIdentifier_t *aid = NULL;
    ByteArray *aid_ba = NULL;
    ByteArray *body = NULL;
    Pkcs12Ctx *storage = NULL;
    Pkcs12Ctx *reopened = NULL;

    /* 1. Алгоритм майбутнього ключа: ДСТУ 4145 (M257 PB) + ГОСТ 28147. */
    ec_params = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);
    cipher_params = gost28147_alloc(GOST28147_SBOX_ID_1);
    CHECK(aid_create_dstu4145(ec_params, cipher_params, true, &aid));
    CHECK(aid_encode(aid, &aid_ba));

    /* 2. Створення сховища (MAC цілісності — ГОСТ 34.311) і генерація ключа. */
    CHECK(pkcs12_create(KS_FILE_PKCS12_WITH_GOST34311, STORAGE_PASSWORD, ROUNDS,
                        &storage));
    CHECK(pkcs12_generate_key(storage, aid_ba));
    CHECK(pkcs12_store_key(storage, "мій ключ", KEY_PASSWORD, ROUNDS));
    printf("Сховище створено, ключ ДСТУ 4145 згенеровано\n");

    /* 3. Серіалізація (сюди ж можна записати сертифікати —
          pkcs12_set_certificates). Далі body зазвичай пишуть у файл
          через ba_to_file(body, "key.p12"). */
    CHECK(pkcs12_encode(storage, &body));
    printf("Розмір контейнера: %u байтів\n", (unsigned)ba_get_len(body));

    /* 4. Відкриття з байтів за паролем і вибір ключа. */
    CHECK(pkcs12_decode(NULL, body, STORAGE_PASSWORD, &reopened));
    CHECK(pkcs12_select_key(reopened, NULL, KEY_PASSWORD));   /* NULL — перший ключ */
    printf("Сховище відкрито, ключ обрано — можна отримувати адаптери\n"
           "(pkcs12_get_sign_adapter / pkcs12_get_verify_adapter / pkcs12_get_dh_adapter)\n");

cleanup:
    pkcs12_free(storage);
    pkcs12_free(reopened);
    aid_free(aid);
    dstu4145_free(ec_params);
    gost28147_free(cipher_params);
    ba_free(aid_ba);
    ba_free(body);
    return (ret == RET_OK) ? 0 : 1;
}
