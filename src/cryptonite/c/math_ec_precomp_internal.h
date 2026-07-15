/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/*
 * Структури таблиць попередніх обчислень для прискорення скалярного
 * множення точки еліптичної кривої на число. Підтримуються два методи
 * (див. opt_level.h):
 *  - віконний метод (WIN): таблиця непарних кратних точки, використовується
 *    разом із NAF-розкладанням скаляра;
 *  - метод гребеня (COMB): таблиця комбінацій точок 2^(i*step) * P.
 * Самі таблиці обчислюються у модулях арифметики кривих
 * (ecp_calc_win_precomp / ecp_calc_comb_precomp та ec2m-аналоги);
 * тут — лише копіювання та звільнення пам'яті.
 */

#ifndef CRYPTONITE_MATH_EC_PRECOMP_H
#define CRYPTONITE_MATH_EC_PRECOMP_H

#include "math_ec_point_internal.h"

# ifdef  __cplusplus
extern "C" {
# endif

/** Тип попередніх обчислень. */
typedef enum EcPrecompType_st {
    EC_PRECOMP_TYPE_WIN,    /**< віконний метод */
    EC_PRECOMP_TYPE_COMB    /**< метод гребеня */
} EcPrecompType;

/**
 * Попередні обчислення для віконного методу:
 * precomp[i] = (2i + 1) * P, i = 0 .. 2^(win_width - 2) - 1.
 */
typedef struct EcPrecompWin_st {
    ECPoint **precomp;    /**< таблиця непарних кратних точки в афінних координатах */
    int precomp_len;      /**< кількість точок у таблиці (2^(win_width - 2)) */
    int win_width;        /**< ширина вікна NAF-розкладання */
} EcPrecompWin;

/**
 * Попередні обчислення для методу гребеня:
 * precomp[i - 1] = sum(bit_j(i) * 2^(j*step) * P), i = 1 .. 2^comb_width - 1,
 * де step — крок гребеня (довжина скаляра в бітах, поділена на comb_width).
 */
typedef struct EcPrecompComb_st {
    ECPoint **precomp;    /**< таблиця комбінацій точок в афінних координатах */
    int comb_width;       /**< ширина гребеня (кількість зубців) */
} EcPrecompComb;

/** Попередні обчислення (обгортка над одним із методів). */
typedef struct EcPrecomp_st {
    EcPrecompType type;
    union {
        EcPrecompWin *win;
        EcPrecompComb *comb;
    } ctx;
} EcPrecomp;

/**
 * Створює копію контексту попередніх обчислень.
 *
 * @param ctx контекст попередні обчислення
 * @return копія контексту
 */
EcPrecomp *ec_copy_precomp_with_alloc(EcPrecomp *precomp_p);

/**
 * Звільняє контекст попередніх обчислень разом з усіма точками таблиці.
 *
 * @param precomp контекст попередніх обчислень
 */
void ec_precomp_free(EcPrecomp *precomp);

#ifdef  __cplusplus
}
#endif

#endif
