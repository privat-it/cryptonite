/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_DSTU4145_PARAMS_H
#define CRYPTONITE_DSTU4145_PARAMS_H

#include <stdint.h>
#include <stdbool.h>

#include "byte_array.h"
#include "word_internal.h"
#include "math_ec_point_internal.h"
#include "math_ec2m_internal.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Стандартний набір параметрів кривої ДСТУ 4145 у «сирому» вигляді
 * (див. таблиці у dstu4145_params_internal.c).
 */
typedef struct Dstu4145DefaultParamsCtx_st {
    int f[5];              /**< Степені ненульових членів многочлена f(t) основного поля (перший елемент — m). */
    int a;                 /**< Коефіцієнт a рівняння кривої (0 або 1). */
    uint8_t b[64];         /**< Коефіцієнт b рівняння кривої (little-endian). */
    uint8_t n[64];         /**< Порядок циклічної підгрупи групи точок (little-endian). */
    uint8_t px[64];        /**< X-координата базової точки (little-endian). */
    uint8_t py[64];        /**< Y-координата базової точки (little-endian). */
    bool is_onb;           /**< true — параметри задано в оптимальному нормальному базисі. */
} Dstu4145DefaultParamsCtx;

/** Параметри криптосистеми ДСТУ 4145 у робочому (розгорнутому) вигляді. */
typedef struct Dstu4145ParamsCtx_st {
    bool is_onb;                   /* Чи задані параметри в ОНБ. */
    ECPoint *p;                    /* Базова точка кривої. */
    EcGf2mCtx *ec2m;               /* Контекст арифметики еліптичної кривої над GF(2^m). */
    WordArray *n;                  /* Порядок циклической подгруппы группы точек еліптичної кривої. */
    size_t m;                      /* Степень основного поля. */
    WordArray **to_pb;             /* Матрица для преобразования представления елемента з ОНБ у ПБ. */
    WordArray **to_onb;            /* Матрица для преобразования представления елемента з ПБ у ОНБ. */
    EcPrecomp *precomp_p;          /* Передобчислення для базової точки. */
} Dstu4145ParamsCtx;

struct Dstu4145Ctx_st {
    Dstu4145ParamsCtx *params;     /* Параметри ДСТУ 4145. */
    PrngCtx *prng;                 /* Контекст ГПСЧ. */
    WordArray *priv_key;           /* закритий ключ. */
    ECPoint *pub_key;              /* відкритий ключ. */
    EcPrecomp *precomp_q;          /* Передобчислення для точки відкритого ключа. */
    bool sign_status;              /* Готов ли контекст для формування підпису. */
    bool verify_status;            /* Готов ли контекст для перевірки підпису. */
};

/**
 * Повертає стандартний набір параметрів кривої ДСТУ 4145.
 *
 * @param params_id ідентифікатор стандартних параметрів
 *
 * @return набір параметрів або NULL для невідомого ідентифікатора
 */
const Dstu4145DefaultParamsCtx *dstu4145_get_defaut_params(Dstu4145ParamsId params_id);

/**
 * Повертає многочлен, який утворює поліноміальний базис для поля GF(2^m) з ОНБ.
 *
 * @param m степінь основного поля
 *
 * @return степені ненульових членів многочлена (за спаданням) або NULL,
 *         якщо для m немає даних ОНБ
 */
const int *dstu4145_get_defaut_f_onb(int m);

/**
 * Ініціалізує дані для роботи з ОНБ: матриці перетворення
 * елементів поля між ОНБ і ПБ (поля to_pb і to_onb).
 *
 * @param params параметри криптосистеми
 * @param m степінь основного поля
 *
 * @return код помилки
 */
int init_onb_params(Dstu4145ParamsCtx *params, int m);

/**
 * Преобразовывает елемент з ОНБ в ПБ.
 *
 * @param params Параметри ДСТУ
 * @param x елемент поля
 */
int onb_to_pb(const Dstu4145ParamsCtx *params, WordArray *x);

/**
 * Выполняет преобразование элемента поля GF(2^m) из ПБ в ОНБ.
 *
 * @param params параметры криптосистемы
 * @param x элемент поля
 */
int pb_to_onb(const Dstu4145ParamsCtx *params, WordArray *x);

/**
 * Відновлює координати точки відкритого ключа з її стисненого подання.
 *
 * @param params параметри криптосистеми
 * @param q стиснене подання відкритого ключа
 * @param qx X-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 *
 * @return код помилки (RET_INVALID_PUBLIC_KEY, якщо q не задає точку на кривій)
 */
int dstu4145_decompress_pubkey_core(const Dstu4145ParamsCtx *params, const ByteArray *q, ByteArray **qx,
        ByteArray **qy);

#ifdef  __cplusplus
}
#endif

#endif
