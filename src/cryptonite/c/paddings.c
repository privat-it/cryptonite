/*
 * Схеми доповнення (padding) даних до кратності довжини блока
 * блокового шифру:
 *  - PKCS#7: додається N байт зі значенням N (1 <= N <= block_len);
 *  - ISO/IEC 7816-4: додається байт-маркер 0x80, далі нульові байти.
 * Доповнення додається завжди: якщо довжина даних уже кратна блоку,
 * додається цілий блок.
 */

#include <memory.h>

#include "paddings.h"
#include "byte_array_internal.h"
#include "macros_internal.h"

/*
 * Додає доповнення PKCS#7: N байт зі значенням N,
 * де N = block_len - data->len % block_len.
 * Результат — новостворений масив data || padding.
 */
int make_pkcs7_padding(const ByteArray *data, uint8_t block_len, ByteArray **data_with_padding)
{
    ByteArray *padding = NULL;
    uint8_t padd_len = 0;
    int ret = RET_OK;

    CHECK_PARAM(data != NULL);
    CHECK_PARAM(data_with_padding != NULL);

    padd_len = (uint8_t) (block_len - data->len % block_len);

    CHECK_NOT_NULL(padding = ba_alloc_by_len(padd_len));
    DO(ba_set(padding, padd_len));

    CHECK_NOT_NULL(*data_with_padding = ba_join(data, padding));

cleanup:

    ba_free(padding);

    return ret;
}

/*
 * Знімає доповнення PKCS#7: довжина доповнення читається з останнього
 * байта, який відкидається разом з рештою доповнення.
 * Коректність вмісту доповнення не перевіряється — викликач має
 * гарантувати, що дані містять валідне доповнення PKCS#7.
 */
int make_pkcs7_unpadding(const ByteArray *data_with_padding, ByteArray **data_without_padding)
{
    int ret = RET_OK;

    CHECK_PARAM(data_with_padding != NULL);
    CHECK_PARAM(data_without_padding != NULL);

    CHECK_NOT_NULL(*data_without_padding = ba_copy_with_alloc(data_with_padding, 0,
                                               data_with_padding->len -
                                               data_with_padding->buf[data_with_padding->len - 1]));

cleanup:

    return ret;
}

/*
 * Додає доповнення ISO/IEC 7816-4: байт-маркер 0x80, далі нульові байти
 * до кратності block_len.
 */
int make_iso_7816_4_padding(const ByteArray *data, uint8_t block_len, ByteArray **data_with_padding)
{
    ByteArray *padding = NULL;
    uint8_t padd_len = 0;
    int ret = RET_OK;

    CHECK_PARAM(data != NULL);
    CHECK_PARAM(data_with_padding != NULL);

    padd_len = (uint8_t) (block_len - data->len % block_len);

    CHECK_NOT_NULL(padding = ba_alloc_by_len(padd_len));
    DO(ba_set(padding, 0));
    padding->buf[0] = 0x80;

    CHECK_NOT_NULL(*data_with_padding = ba_join(data, padding));

cleanup:

    ba_free(padding);

    return ret;
}

/*
 * Знімає доповнення ISO/IEC 7816-4: відкидає кінцеві нульові байти та
 * байт-маркер перед ними. Передумова: дані містять коректне доповнення
 * (значення байта-маркера не перевіряється).
 */
int make_iso_7816_4_unpadding(const ByteArray *data_with_padding, ByteArray **data_without_padding)
{

    int ret = RET_OK;
    size_t i = 0;

    CHECK_PARAM(data_with_padding != NULL);
    CHECK_PARAM(data_without_padding != NULL);

    i = data_with_padding->len - 1;

    while(data_with_padding->buf[i] == 0){
        --i;
    }

    CHECK_NOT_NULL(*data_without_padding = ba_copy_with_alloc(data_with_padding, 0, i));

cleanup:

    return ret;
}
