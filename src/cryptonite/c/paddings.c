#include <memory.h>

#include "paddings.h"
#include "byte_array_internal.h"
#include "macros_internal.h"

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

//ISO/IEC 7816-4
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
