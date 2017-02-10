/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_RS_H
#define CRYPTONITE_RS_H

#include "byte_array.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Заповнює масив випадковими байтами використовуючи системний ГПВЧ.
 *
 * @param buf масив для розміщення випадкових байт
 * @return код помилки
 */
CRYPTONITE_EXPORT int rs_std_next_bytes(ByteArray *buf);

/**
 * Заповнює масив випадковими байтами на основі непередбачуваності часу зчитування з оперативної пам'яті фіксованого числа байт.
 *
 * @param buf масив для розміщення випадкових байт
 * @return код помилки
 */
CRYPTONITE_EXPORT int rs_memory_next_bytes(ByteArray *buf);

#ifdef  __cplusplus
}
#endif

#endif
