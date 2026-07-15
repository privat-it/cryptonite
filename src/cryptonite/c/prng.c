/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/*
 * Реалізація загального інтерфейсу ГПВЧ (див. prng.h).
 *
 * PrngCtx — тонка обгортка, яка за полем mode_id диспетчеризує виклики до
 * конкретного алгоритму генерації. Наразі обидва режими (PRNG_MODE_DEFAULT
 * та PRNG_MODE_DSTU) використовують один внутрішній генератор за схемою
 * ДСТУ 4145 (dstu4145_prng_internal.c), побудований на блоковому шифрі
 * ГОСТ 28147-89 у режимі ECB: стартовий seed (щонайменше 40 байт) задає
 * ключ шифрування та початковий внутрішній стан, а додаткова випадковість
 * домішується у стан через prng_seed за допомогою гешування ГОСТ 34.311.
 */

#include "prng.h"

#include "macros_internal.h"
#include "dstu4145_prng_internal.h"
#include "byte_array_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/prng.c"

/* Контекст ГПВЧ: ідентифікатор режиму та контекст відповідного генератора. */
struct PrngCtx_st {
    PrngMode mode_id;
    union {
        Dstu4145PrngCtx *dstu;
    } mode;
};

/*
 * Створює контекст ГПВЧ обраного режиму.
 * Передумова: seed щонайменше 40 байт (перші 32 байти стають ключем
 * ГОСТ 28147-89, наступні 8 — початковим станом генератора).
 * У разі помилки повертає NULL.
 */
PrngCtx *prng_alloc(PrngMode mode, const ByteArray *seed)
{
    PrngCtx *ctx = NULL;
    int ret = RET_OK;

    CHECK_PARAM(seed != NULL);
    CHECK_PARAM(seed->len >= 40);

    CALLOC_CHECKED(ctx, sizeof(PrngCtx));
    switch (mode) {
        case PRNG_MODE_DEFAULT:
        case PRNG_MODE_DSTU:
            ctx->mode_id = mode;
            CHECK_NOT_NULL(ctx->mode.dstu = dstu4145_prng_alloc(seed));
            break;
        default:
            SET_ERROR(RET_INVALID_PARAM);
    }

cleanup:

    if (ret != RET_OK) {
        prng_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

/* Повертає ідентифікатор режиму роботи генератора. */
int prng_get_mode(PrngCtx *prng, PrngMode *mode)
{
    int ret = RET_OK;

    CHECK_PARAM(prng != NULL);
    CHECK_PARAM(mode != NULL);

    *mode = prng->mode_id;

cleanup:

    return ret;
}

/*
 * Домішує додаткову випадковість у внутрішній стан генератора;
 * делегує виклик dstu4145_prng_seed.
 */
int prng_seed(PrngCtx *prng, const ByteArray *seed)
{
    int ret = RET_OK;

    CHECK_PARAM(prng != NULL);
    CHECK_PARAM(seed != NULL);

    switch (prng->mode_id) {
    case PRNG_MODE_DEFAULT:
    case PRNG_MODE_DSTU:
        if (prng->mode.dstu == NULL) {
            SET_ERROR(RET_INVALID_CTX);
        }
        DO(dstu4145_prng_seed(prng->mode.dstu, seed));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX);
    }

cleanup:

    return ret;
}

/* Заповнює buf псевдовипадковими байтами (рівно buf->len байт). */
int prng_next_bytes(PrngCtx *prng, ByteArray *buf)
{
    int ret = RET_OK;

    CHECK_PARAM(prng != NULL);
    CHECK_PARAM(buf != NULL);

    switch (prng->mode_id) {
    case PRNG_MODE_DEFAULT:
    case PRNG_MODE_DSTU:
        if (prng->mode.dstu == NULL) {
            SET_ERROR(RET_INVALID_CTX);
        }
        DO(dstu4145_prng_next_bytes(prng->mode.dstu, buf));
        break;
    default:
        SET_ERROR(RET_INVALID_CTX);
    }

cleanup:

    return ret;
}

/* Звільняє контекст ГПВЧ разом із внутрішнім контекстом генератора. */
void prng_free(PrngCtx *prng)
{
    if (prng != NULL) {
        switch (prng->mode_id) {
        case PRNG_MODE_DEFAULT:
        case PRNG_MODE_DSTU:
            if (prng->mode.dstu != NULL) {
                dstu4145_prng_free(prng->mode.dstu);
            }
        }

        free(prng);
    }
}
