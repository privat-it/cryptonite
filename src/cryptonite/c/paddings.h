#ifndef CRYPTONITE_PADDINGS_H
#define CRYPTONITE_PADDINGS_H

#include "byte_array.h"

#ifdef  __cplusplus
extern "C" {
#endif

CRYPTONITE_EXPORT int make_pkcs7_padding(const ByteArray *data, uint8_t block_len, ByteArray **data_with_padding);

CRYPTONITE_EXPORT int make_pkcs7_unpadding(const ByteArray *data_with_padding, ByteArray **data_without_padding);

CRYPTONITE_EXPORT int make_iso_7816_4_padding(const ByteArray *data, uint8_t block_len, ByteArray **data_with_padding);

CRYPTONITE_EXPORT int make_iso_7816_4_unpadding(const ByteArray *data_with_padding, ByteArray **data_without_padding);

#ifdef  __cplusplus
}
#endif

#endif //CRYPTONITE_PADDINGS_H
