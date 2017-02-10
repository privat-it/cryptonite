/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef SRC_API_PKIX_MACROS_H_
#define SRC_API_PKIX_MACROS_H_

#include "pkix_errors.h"
#include "macros_internal.h"

#define DO_ASN(func, _ret)                               \
    {                                                    \
        _ret = (func);                                   \
        if (_ret != 0) {                                 \
            _ret = RET_ASN1_ERROR;                       \
            goto cleanup;                                \
        }                                                \
    }

/**
 * Перевернуть данные по указателю побайтно.
 *
 * Также работает когда источник совпадает с приемником.
 *
 * @param size размер данных в байтах
 */
#define SWAP_BYTES(src, dst, size)                            \
    {                                                         \
        int _size = size;                                     \
        uint8_t *_src_start = (uint8_t *)(src);               \
        uint8_t *_src_end = (uint8_t *)(src) + _size - 1;     \
        uint8_t *_dst_start = (uint8_t *)(dst);               \
        uint8_t *_dst_end = (uint8_t *)(dst) + _size - 1;     \
        while (_src_start <= _src_end) {                      \
            uint8_t _tmp = *_src_start++;                     \
            *_dst_start++ = *_src_end--;                      \
            *_dst_end-- = _tmp;                               \
        }                                                     \
    }

#endif /* SRC_API_PKIX_MACROS_H_ */
