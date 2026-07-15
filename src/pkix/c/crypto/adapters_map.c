/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/*
 * Огляд модуля.
 *
 * Відповідність адаптерів гешування та формування підпису. AdaptersMap
 * зберігає два паралельних масиви однакової довжини - digest[] і sign[], -
 * у яких елемент digest[i] відповідає елементу sign[i]. Структура дозволяє
 * тримати впорядкований набір пар "геш-адаптер <-> підпис-адаптер" і
 * використовується як довідник під час добору потрібної реалізації.
 */

#include "adapters_map.h"

#include "pkix_macros_internal.h"
#include "log_internal.h"
#include "cryptonite_manager.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/crypto/adapters_map.c"

/**
 * Виділяє порожній обʼєкт AdaptersMap з нульовим лічильником і порожніми
 * масивами адаптерів.
 *
 * @return вказівник на створений обʼєкт або NULL у разі помилки
 */
AdaptersMap *adapters_map_alloc(void)
{
    int ret;
    AdaptersMap *out = NULL;

    LOG_ENTRY();

    CALLOC_CHECKED(out, sizeof(AdaptersMap));

cleanup:

    return out;
}

/**
 * Звільняє AdaptersMap разом з усіма адаптерами, на які він посилається:
 * для кожної пари викликає digest_adapter_free() та sign_adapter_free(),
 * потім звільняє самі масиви й структуру.
 *
 * @param adapters контекст, що звільняється (може бути NULL)
 */
void adapters_map_free(AdaptersMap *adapters)
{
    int i;

    LOG_ENTRY();

    if (adapters) {
        for (i = 0; i < adapters->count; i++) {
            digest_adapter_free(adapters->digest[i]);
            sign_adapter_free(adapters->sign[i]);
        }

        free(adapters->digest);
        free(adapters->sign);
        free(adapters);
    }
}

/**
 * Звільняє лише саму структуру AdaptersMap та її масиви, не чіпаючи адаптери,
 * на які вона посилається (їх час життя контролюється зовні).
 *
 * @param adapters контекст, що звільняється (може бути NULL)
 */
void adapters_map_with_const_content_free(AdaptersMap *adapters)
{
    LOG_ENTRY();

    if (adapters) {
        free(adapters->digest);
        free(adapters->sign);
        free(adapters);
    }
}

/**
 * Додає пару адаптерів у кінець мапи: збільшує лічильник, розширює обидва
 * масиви (REALLOC) і записує digest та sign в нову позицію. Право власності
 * на передані адаптери переходить до мапи.
 *
 * @param adapter_map мапа адаптерів
 * @param digest      адаптер гешування
 * @param sign        адаптер формування підпису
 *
 * @return код помилки
 */
int adapters_map_add(AdaptersMap *adapter_map, DigestAdapter *digest, SignAdapter *sign)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(adapter_map != NULL);
    CHECK_PARAM(digest != NULL);
    CHECK_PARAM(sign != NULL);

    adapter_map->count++;
    REALLOC_CHECKED(adapter_map->digest, adapter_map->count * sizeof(DigestAdapter *), adapter_map->digest);
    REALLOC_CHECKED(adapter_map->sign, adapter_map->count * sizeof(SignAdapter *), adapter_map->sign);

    adapter_map->digest[adapter_map->count - 1] = digest;
    adapter_map->sign[adapter_map->count - 1] = sign;

cleanup:

    return ret;
}
