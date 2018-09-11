//
// Created by paradaimu on 9/6/18.
//

#ifndef CRYPTONITE_GOST3410_H
#define CRYPTONITE_GOST3410_H

#ifdef  __cplusplus
extern "C" {
#endif

#include "byte_array.h"
#include "prng.h"
#include "opt_level.h"

typedef struct Gost3410Ctx_st Gost3410Ctx;

typedef enum {
    GOST3410_PARAMS_ID_1 = 1,
    GOST3410_PARAMS_ID_2 = 2,
    GOST3410_PARAMS_ID_3 = 3,
    GOST3410_PARAMS_ID_4 = 4,
    GOST3410_PARAMS_ID_5 = 5,
} Gost3410ParamsId;

/**
 * Створює контекст GOST3410 зі стандартними параметрами.
 *
 * @param params_id ідентифікатор стандартних параметрів
 * @return контекст GOST3410
 */
CRYPTONITE_EXPORT Gost3410Ctx *gost3410_alloc(Gost3410ParamsId id);

/**
 * Створює контекст GOST3410 зі стандартними параметрами.
 *
 * @param params_id ідентифікатор стандартних параметрів
 * @return контекст GOST3410
 */
CRYPTONITE_EXPORT Gost3410Ctx *gost3410_alloc_with_params(const ByteArray *p, const ByteArray *a, const ByteArray *b, const ByteArray *q, const ByteArray *px, const ByteArray *py);

/**
 * Генерує закритий ключ GOST3410.
 *
 * @param ctx контекст GOST3410
 * @param prng контекст ГПСЧ
 * @param d закритий ключ GOST3410
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost3410_generate_privkey(Gost3410Ctx *ctx, PrngCtx *prng, ByteArray **d);


/**
 * Ініціалізує контекст для формування підпису.
 *
 * @param ctx контекст GOST3410
 * @param d закритий ключ
 * @param prng контекст ГПСЧ
 * @return код помилки
 */
int gost3410_init_sign(Gost3410Ctx *ctx, const ByteArray *d, PrngCtx *prng);

/**
 * Формує підпис по гешу.
 *
 * @param ctx контекст GOST3410
 * @param hash геш
 * @param r частина підпису
 * @param s частина підпису
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost3410_sign(Gost3410Ctx *ctx, const ByteArray *hash, ByteArray **r, ByteArray **s);

CRYPTONITE_EXPORT int gost3410_compress_pubkey(Gost3410Ctx *ctx, const ByteArray *qx, const ByteArray *qy, ByteArray **q, int *last_qy_bit);

CRYPTONITE_EXPORT int gost3410_decompress_pubkey(Gost3410Ctx *ctx, const ByteArray *q, int last_qy_bit, ByteArray **qx,
                                              ByteArray **qy);

CRYPTONITE_EXPORT int gost3410_set_opt_level(Gost3410Ctx *ctx, OptLevelId opt_level);

CRYPTONITE_EXPORT int gost3410_get_pubkey(Gost3410Ctx *ctx, const ByteArray *d, ByteArray **Qx, ByteArray **Qy);

/**
 * Ініціалізує контекст для перевірки підпису.
 *
 * @param ctx контекст GOST3410
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost3410_init_verify(Gost3410Ctx *ctx, const ByteArray *qx, const ByteArray *qy);

/**
 * Виконує перевірку підпису по гешу від даних.
 *
 * @param ctx контекст GOST3410
 * @param hash геш
 * @param r частина підпису
 * @param s частина підпису
 *  * @return код помилки або RET_OK, якщо підпис вірний
 */
CRYPTONITE_EXPORT int gost3410_verify(Gost3410Ctx *ctx, const ByteArray *hash, const ByteArray *r, const ByteArray *s);


/**
 * Звільняє контекст GOST3410.
 *
 * @param ctx контекст GOST3410
 *
 */
CRYPTONITE_EXPORT void gost3410_free(Gost3410Ctx *ctx);

#ifdef  __cplusplus
}
#endif

#endif //CRYPTONITE_GOST3410_H
