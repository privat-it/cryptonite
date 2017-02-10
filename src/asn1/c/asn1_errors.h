/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_ASN1_ERRORS_H
#define CRYPTONITE_PKI_ASN1_ERRORS_H

#include "cryptonite_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RET_ASN1_ERROR                           100
/** Ошибка кодирования в байты. */
#define RET_ASN1_ENCODE_ERROR                    101
/** Ошибка декодирования из байт. */
#define RET_ASN1_DECODE_ERROR                    102

#ifdef __cplusplus
}
#endif

#endif
