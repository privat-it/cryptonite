/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/*
 * Точка еліптичної кривої та базові операції над нею як над структурою даних
 * (виділення, копіювання, обнулення, звільнення пам'яті).
 *
 * Точка зберігається у проєктивних координатах (X, Y, Z); конкретна
 * інтерпретація координат задається модулями арифметики кривих:
 * якобіанські координати (x = X/Z^2, y = Y/Z^3) для кривих над GF(p)
 * (math_ecp_internal) та координати Лопеса-Дахаба (x = X/Z, y = Y/Z^2)
 * для кривих над GF(2^m) (math_ec2m_internal). Афінна точка подається
 * як (X, Y, 1). Жодних обчислень у полі цей модуль не виконує.
 */

#ifndef CRYPTONITE_MATH_EC_POINT_H
#define CRYPTONITE_MATH_EC_POINT_H

#include "word_internal.h"

#ifdef  __cplusplus
extern "C" {
#endif

/** Точка еліптичної кривої у проєктивних координатах. */
typedef struct ECPoint_st {
    WordArray *x;    /* Проєктивна координата X. */
    WordArray *y;    /* Проєктивна координата Y. */
    WordArray *z;    /* Проєктивна координата Z (для афінної точки Z = 1). */
} ECPoint;

/**
 * Створює точку з нульовими координатами X, Y, Z заданої довжини.
 *
 * @param len довжина координат у машинних словах
 * @return точка або NULL у разі помилки
 */
ECPoint *ec_point_alloc(size_t len);

/**
 * Створює точку за афінними координатами (Z ініціалізується одиницею).
 *
 * @param px x-координата точки
 * @param py y-координата точки
 * @return точка або NULL у разі помилки
 */
ECPoint *ec_point_aff_alloc(const WordArray *px, const WordArray *py);

/**
 * Створює точку за проєктивними координатами.
 *
 * @param px проєктивна координата X
 * @param py проєктивна координата Y
 * @param pz проєктивна координата Z
 * @return точка або NULL у разі помилки
 */
ECPoint *ec_point_proj_alloc(const WordArray *px, const WordArray *py, const WordArray *pz);

/**
 * Встановлює точку в нейтральний елемент групи (точку на нескінченності),
 * яка подається трійкою (0, 0, 1).
 *
 * @param p точка еліптичної кривої
 */
void ec_point_zero(ECPoint *p);

/**
 * Копіює координати точки в раніше створену точку такої самої довжини.
 *
 * @param a точка-джерело
 * @param out точка-приймач
 */
void ec_point_copy(const ECPoint *a, ECPoint *out);

/**
 * Створює копію точки.
 *
 * @param a точка еліптичної кривої
 * @return копія точки або NULL у разі помилки
 */
ECPoint *ec_point_copy_with_alloc(const ECPoint *a);

/**
 * Звільняє пам'ять, яку займає точка.
 *
 * @param p точка еліптичної кривої
 */
void ec_point_free(ECPoint *p);

#ifdef  __cplusplus
}
#endif

#endif
