/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_BASE64_H
#define CRYPTONITE_BASE64_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

char *base64_encode(const uint8_t *data, size_t input_length, size_t *output_length);
uint8_t *base64_decode(const char *data, size_t input_length, size_t *output_length);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTONITE_BASE64_H */

