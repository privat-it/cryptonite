/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_DSTU4145_H
#define CRYPTONITE_DSTU4145_H

#include <stdbool.h>

#include "byte_array.h"
#include "prng.h"
#include "opt_level.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct Dstu4145Ctx_st Dstu4145Ctx;

/**
 * Ідентифікатори стандартних параметрів ДСТУ 4145.
 */
typedef enum {
    DSTU4145_PARAMS_ID_M163_PB = 1,
    DSTU4145_PARAMS_ID_M167_PB = 2,
    DSTU4145_PARAMS_ID_M173_PB = 3,
    DSTU4145_PARAMS_ID_M179_PB = 4,
    DSTU4145_PARAMS_ID_M191_PB = 5,
    DSTU4145_PARAMS_ID_M233_PB = 6,
    DSTU4145_PARAMS_ID_M257_PB = 7,
    DSTU4145_PARAMS_ID_M307_PB = 8,
    DSTU4145_PARAMS_ID_M367_PB = 9,
    DSTU4145_PARAMS_ID_M431_PB = 10,
    DSTU4145_PARAMS_ID_M173_ONB = 11,
    DSTU4145_PARAMS_ID_M179_ONB = 12,
    DSTU4145_PARAMS_ID_M191_ONB = 13,
    DSTU4145_PARAMS_ID_M233_ONB = 14,
    DSTU4145_PARAMS_ID_M431_ONB = 15
} Dstu4145ParamsId;

/**
 * Створює контекст ДСТУ 4145 зі стандартними параметрами.
 *
 * @param params_id ідентифікатор стандартних параметрів
 * @return контекст ДСТУ 4145
 */
CRYPTONITE_EXPORT Dstu4145Ctx *dstu4145_alloc(Dstu4145ParamsId params_id);

/**
 * Створює контекст ДСТУ 4145 з параметрами у поліноміальному базисі.
 *
 * @param f примітивний многочлен f(t) (тричлен, п'ятичлен), який визначає поліноміальний базис
 * @param f_len число членів у полиномі f (3 або 5)
 * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param n порядок циклічної підгрупи групи точок еліптичної кривої
 * @param px X-координата точки еліптичної кривої порядока n
 * @param py Y-координата точки еліптичної кривої порядока n
 *
 * @return контекст ДСТУ 4145
 */
CRYPTONITE_EXPORT Dstu4145Ctx *dstu4145_alloc_pb(const int *f, size_t f_len, int a, const ByteArray *b,
        const ByteArray *n, const ByteArray *px, const ByteArray *py);

/**
 * Створює контекст ДСТУ 4145 з параметрами у оптимальному нормальному базисі.
 *
 * @param m степінь основного поля, непарне просте число (163 <= m <= 509)
 * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param n порядок циклічної підгрупи групи точок еліптичної кривої
 * @param px X-координата точки еліптичної кривої порядока n
 * @param py Y-координата точки еліптичної кривої порядока n
 *
 * @return контекст ДСТУ 4145
 */
CRYPTONITE_EXPORT Dstu4145Ctx *dstu4145_alloc_onb(const int m, int a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py);

/**
 * Повертає параметри ДСТУ 4145.
 *
 * @param ctx контекст ДСТУ 4145
 * @param f примітивний многочлен f(t) (тричлен, п'ятичлен), який визначає поліноміальний базис
 * @param f_len число членів у полиномі f (3 або 5)
 * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param n порядок циклічної підгрупи групи точок еліптичної кривої
 * @param px X-координата точки еліптичної кривої порядока n
 * @param py Y-координата точки еліптичної кривої порядока n
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu4145_get_params(const Dstu4145Ctx *ctx, int **f, size_t *f_len, int *a, ByteArray **b,
        ByteArray **n, ByteArray **px, ByteArray **py);

/**
 * Визначає чи є параметри ДСТУ 4145 ОНБ.
 *
 * @param ctx контекст ДСТУ 4145
 * @param is_onb_params чи є параметри ДСТУ 4145 ОНБ
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu4145_is_onb_params(const Dstu4145Ctx *ctx, bool *is_onb_params);

/**
 * Визначає чи параметри однакові.
 *
 * @param param_a контекст ДСТУ 4145
 * @param param_b контекст ДСТУ 4145
 * @param equals чи параметри однакові
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu4145_equals_params(const Dstu4145Ctx *param_a, const Dstu4145Ctx *param_b, bool *equals);

/**
 * Копіює параметри.
 *
 * @param param контекст ДСТУ 4145
 * @return контекст ДСТУ 4145
 */
CRYPTONITE_EXPORT Dstu4145Ctx *dstu4145_copy_params_with_alloc(const Dstu4145Ctx *param);

/**
 * Копіює контекст ДСТУ 4145.
 *
 * @param param контекст ДСТУ 4145
 * @return контекст ДСТУ 4145
 */
CRYPTONITE_EXPORT Dstu4145Ctx *dstu4145_copy_with_alloc(const Dstu4145Ctx *param);

/**
 * Генерує закритий ключ ДСТУ 4145.
 *
 * @param ctx контекст ДСТУ 4145
 * @param prng контекст ГПСЧ
 * @param d закритий ключ ДСТУ 4145
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu4145_generate_privkey(const Dstu4145Ctx *ctx, PrngCtx *prng, ByteArray **d);

/**
 * Формує відкритий ключ за закритим.
 *
 * @param ctx контекст ДСТУ 4145
 * @param d закритий ключ
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu4145_get_pubkey(const Dstu4145Ctx *ctx, const ByteArray *d, ByteArray **qx, ByteArray **qy);

/**
 * Формує стисле представлення відкритого ключа.
 *
 * @param ctx контекст ДСТУ 4145
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @param q стисле представлення відкритого ключа
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu4145_compress_pubkey(const Dstu4145Ctx *ctx, const ByteArray *qx, const ByteArray *qy,
        ByteArray **q);

/**
 * Формує розгорнуте представлення відкритого ключа.
 *
 * @param ctx контекст ДСТУ 4145
 * @param q стисле представлення відкритого ключа
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu4145_decompress_pubkey(const Dstu4145Ctx *ctx, const ByteArray *q, ByteArray **qx,
        ByteArray **qy);

/**
 * Встановити рівень передобчислення.
 *
 * @param ctx контекст ДСТУ 4145
 * @param opt_level рівень передобчислення
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu4145_set_opt_level(Dstu4145Ctx *ctx, OptLevelId opt_level);

/**
 * Ініціалізує контекст для формування підписів.
 *
 * @param ctx контекст ДСТУ 4145
 * @param d закритий ключ
 * @param prng контекст ГПСЧ
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu4145_init_sign(Dstu4145Ctx *ctx, const ByteArray *d, PrngCtx *prng);

/**
 * Формує підпис по гешу.
 *
 * @param ctx контекст ДСТУ 4145
 * @param hash геш
 * @param r частина підпису
 * @param s частину підпису
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu4145_sign(const Dstu4145Ctx *ctx, const ByteArray *hash, ByteArray **r, ByteArray **s);

/**
 * Ініціалізує контекст для перевірки підписів.
 *
 * @param ctx контекст ДСТУ 4145
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu4145_init_verify(Dstu4145Ctx *ctx, const ByteArray *qx, const ByteArray *qy);

/**
 * Виконує перевірку підпису з гешу від даних.
 *
 * @param ctx контекст ДСТУ 4145
 * @param hash геш
 * @param r частина підпису
 * @param s частина підпису
 * @return код помилки або RET_OK, якщо підпис вірний
 */
CRYPTONITE_EXPORT int dstu4145_verify(const Dstu4145Ctx *ctx, const ByteArray *hash, const ByteArray *r,
        const ByteArray *s);

/**
 * Повертає загальне секретне значення по схемі Диффі-Хеллмана з кофактором згідно ДСТУ 4145.
 *
 * @param ctx контекст ДСТУ 4145
 * @param with_cofactor алгоритм з кофакторним множенням
 * @param d закритий ключ
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @param zx Х-координата спільного секретного значення
 * @param zy Y-координата спільного секретного значення
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu4145_dh(const Dstu4145Ctx *ctx, bool with_cofactor, const ByteArray *d, const ByteArray *qx,
        const ByteArray *qy, ByteArray **zx, ByteArray **zy);

/**
 * Звільняє контекст ДСТУ 4145.
 *
 * @param ctx контекст ДСТУ 4145
 */
CRYPTONITE_EXPORT void dstu4145_free(Dstu4145Ctx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
