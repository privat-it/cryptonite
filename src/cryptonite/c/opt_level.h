/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_OPT_LEVEL_H
#define CRYPTONITE_OPT_LEVEL_H

typedef enum {
    OPT_LEVEL_COMB_5_WIN_5 = 0x5005,
    OPT_LEVEL_COMB_11_WIN_5 = 0xb005,
    OPT_LEVEL_WIN_5_WIN_5 = 0x0505,
    OPT_LEVEL_WIN_11_WIN_11 = 0x0b0b,
    OPT_LEVEL_COMB_5_COMB_5 = 0x5050,
    OPT_LEVEL_COMB_11_COMB_11 = 0xb0b0
} OptLevelId;

#endif
