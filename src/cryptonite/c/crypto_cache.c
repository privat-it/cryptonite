/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/*
 * Кеш криптографічних контекстів ДСТУ 4145 та ECDSA.
 *
 * Створення контексту з увімкненими передобчисленнями (opt_level) —
 * коштовна операція, тому готові контексти зберігаються у чотирьох
 * однозв'язних списках:
 *  - ДСТУ 4145 за ідентифікатором стандартних параметрів;
 *  - ДСТУ 4145 за довільними параметрами у поліноміальному базисі (ПБ);
 *  - ДСТУ 4145 за довільними параметрами в оптимальному нормальному
 *    базисі (ОНБ);
 *  - ECDSA за довільними параметрами кривої над простим полем.
 *
 * Пошук — лінійний перебір списку з порівнянням усіх параметрів кривої.
 * Функції crypto_cache_get_* повертають не сам кешований контекст, а його
 * копію (dstu4145_copy_params_with_alloc / ecdsa_copy_params_with_alloc),
 * тож викликач володіє результатом і звільняє його самостійно.
 * Якщо контексту немає в кеші, а default_opt_level != 0, контекст
 * створюється і додається в кеш «ліниво» під час першого запиту.
 *
 * Потокобезпека: додавання елементів захищено окремим pthread-м'ютексом
 * для кожного списку; пошук виконується без блокування (списки лише
 * доповнюються в кінець аж до виклику crypto_cache_free).
 */

#include <string.h>

#include "crypto_cache.h"
#include "crypto_cache_internal.h"
#include "pthread_internal.h"
#include "macros_internal.h"
#include "dstu4145_internal.h"
#include "ecdsa_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/crypto_cache.c"

/* Елемент кешу контекстів ДСТУ 4145 зі стандартними параметрами (ключ — params_id). */
typedef struct Dstu4145CacheById_st {
    Dstu4145ParamsId params_id;
    Dstu4145Ctx *ctx;
    struct Dstu4145CacheById_st *next;
} Dstu4145CacheById;

static Dstu4145CacheById *dstu4145_cache_by_id = NULL;
static pthread_mutex_t dstu4145_cache_by_id_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Елемент кешу контекстів ДСТУ 4145 з довільними параметрами у ПБ (ключ — копії параметрів кривої). */
typedef struct Dstu4145CacheByPb_st {
    int *f;
    size_t f_len;
    int a;
    ByteArray *b;
    ByteArray *n;
    ByteArray *px;
    ByteArray *py;
    Dstu4145Ctx *ctx;
    struct Dstu4145CacheByPb_st *next;
} Dstu4145CacheByPb;

static Dstu4145CacheByPb *dstu4145_cache_by_pb = NULL;
static pthread_mutex_t dstu4145_cache_by_pb_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Елемент кешу контекстів ДСТУ 4145 з довільними параметрами в ОНБ. */
typedef struct Dstu4145CacheByOnb_st {
    int m;
    int a;
    ByteArray *b;
    ByteArray *n;
    ByteArray *px;
    ByteArray *py;
    Dstu4145Ctx *ctx;
    struct Dstu4145CacheByOnb_st *next;
} Dstu4145CacheByOnb;

static Dstu4145CacheByOnb *dstu4145_cache_by_onb = NULL;
static pthread_mutex_t dstu4145_cache_by_onb_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Елемент кешу контекстів ECDSA (ключ — параметри кривої над простим полем). */
typedef struct EcdsaCache_st {
    ByteArray *p;
    ByteArray *a;
    ByteArray *b;
    ByteArray *q;
    ByteArray *px;
    ByteArray *py;
    EcdsaCtx *ctx;
    struct EcdsaCache_st *next;
} EcdsaCache;

static EcdsaCache *ecdsa_cache = NULL;
static pthread_mutex_t ecdsa_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Рівень оптимізації за замовчуванням: 0 — ліниве кешування вимкнено. */
OptLevelId default_opt_level = 0;

/* Додає елемент у кінець списку кешу за params_id (викликається під відповідним м'ютексом). */
static void dstu4145_cache_id_append(Dstu4145CacheById *dstu4145_cache_by_id_new)
{
    if (dstu4145_cache_by_id) {
        Dstu4145CacheById *dstu4145_cache_by_id_curr = dstu4145_cache_by_id;
        while (dstu4145_cache_by_id_curr->next != NULL) {
            dstu4145_cache_by_id_curr = dstu4145_cache_by_id_curr->next;
        }
        dstu4145_cache_by_id_curr->next = dstu4145_cache_by_id_new;
    } else {
        dstu4145_cache_by_id = dstu4145_cache_by_id_new;
    }
}

/* Додає елемент у кінець списку кешу параметрів у ПБ (викликається під відповідним м'ютексом). */
static void dstu4145_cache_pb_append(Dstu4145CacheByPb *dstu4145_cache_by_pb_new)
{
    if (dstu4145_cache_by_pb) {
        Dstu4145CacheByPb *dstu4145_cache_by_pb_curr = dstu4145_cache_by_pb;
        while (dstu4145_cache_by_pb_curr->next != NULL) {
            dstu4145_cache_by_pb_curr = dstu4145_cache_by_pb_curr->next;
        }
        dstu4145_cache_by_pb_curr->next = dstu4145_cache_by_pb_new;
    } else {
        dstu4145_cache_by_pb = dstu4145_cache_by_pb_new;
    }
}

/* Додає елемент у кінець списку кешу параметрів в ОНБ (викликається під відповідним м'ютексом). */
static void dstu4145_cache_onb_append(Dstu4145CacheByOnb *dstu4145_cache_by_onb_new)
{
    if (dstu4145_cache_by_onb) {
        Dstu4145CacheByOnb *dstu4145_cache_by_onb_curr = dstu4145_cache_by_onb;
        while (dstu4145_cache_by_onb_curr->next != NULL) {
            dstu4145_cache_by_onb_curr = dstu4145_cache_by_onb_curr->next;
        }
        dstu4145_cache_by_onb_curr->next = dstu4145_cache_by_onb_new;
    } else {
        dstu4145_cache_by_onb = dstu4145_cache_by_onb_new;
    }
}

/* Додає елемент у кінець списку кешу ECDSA (викликається під відповідним м'ютексом). */
static void ecdsa_cache_append(EcdsaCache *ecdsa_cache_new)
{
    if (ecdsa_cache) {
        EcdsaCache *ecdsa_cache_curr = ecdsa_cache;
        while (ecdsa_cache_curr->next != NULL) {
            ecdsa_cache_curr = ecdsa_cache_curr->next;
        }
        ecdsa_cache_curr->next = ecdsa_cache_new;
    } else {
        ecdsa_cache = ecdsa_cache_new;
    }
}

/* Шукає елемент кешу за ідентифікатором стандартних параметрів; NULL, якщо не знайдено. */
static Dstu4145CacheById *dstu4145_cache_get_element_by_id(Dstu4145ParamsId params_id)
{
    if (dstu4145_cache_by_id) {
        Dstu4145CacheById *dstu4145_cache_by_id_curr = dstu4145_cache_by_id;
        while (dstu4145_cache_by_id_curr != NULL) {
            if (dstu4145_cache_by_id_curr->params_id == params_id) {
                return dstu4145_cache_by_id_curr;
            } else {
                dstu4145_cache_by_id_curr = dstu4145_cache_by_id_curr->next;
            }
        }
    }

    return NULL;
}

/* Шукає елемент кешу порівнянням усіх параметрів кривої у ПБ; NULL, якщо не знайдено. */
static Dstu4145CacheByPb *dstu4145_cache_get_element_by_pb(const int *f, size_t f_len, int a, const ByteArray *b,
        const ByteArray *n,
        const ByteArray *px, const ByteArray *py)
{
    if (dstu4145_cache_by_pb) {
        Dstu4145CacheByPb *dstu4145_cache_by_pb_curr = dstu4145_cache_by_pb;
        while (dstu4145_cache_by_pb_curr != NULL) {
            if (dstu4145_cache_by_pb_curr->f_len == f_len
                    && (memcmp(dstu4145_cache_by_pb_curr->f, f, f_len * sizeof(int)) == 0)
                    && dstu4145_cache_by_pb_curr->a == a
                    && (ba_cmp(dstu4145_cache_by_pb_curr->b, b) == 0)
                    && (ba_cmp(dstu4145_cache_by_pb_curr->n, n) == 0)
                    && (ba_cmp(dstu4145_cache_by_pb_curr->px, px) == 0)
                    && (ba_cmp(dstu4145_cache_by_pb_curr->py, py) == 0)) {
                return dstu4145_cache_by_pb_curr;
            } else {
                dstu4145_cache_by_pb_curr = dstu4145_cache_by_pb_curr->next;
            }
        }
    }

    return NULL;
}

/* Шукає елемент кешу порівнянням усіх параметрів кривої в ОНБ; NULL, якщо не знайдено. */
static Dstu4145CacheByOnb *dstu4145_cache_get_element_by_onb(const int m, int a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py)
{
    if (dstu4145_cache_by_onb) {
        Dstu4145CacheByOnb *dstu4145_cache_by_onb_curr = dstu4145_cache_by_onb;
        while (dstu4145_cache_by_onb_curr != NULL) {
            if (dstu4145_cache_by_onb_curr->m == m
                    && dstu4145_cache_by_onb_curr->a == a
                    && (ba_cmp(dstu4145_cache_by_onb_curr->b, b) == 0)
                    && (ba_cmp(dstu4145_cache_by_onb_curr->n, n) == 0)
                    && (ba_cmp(dstu4145_cache_by_onb_curr->px, px) == 0)
                    && (ba_cmp(dstu4145_cache_by_onb_curr->py, py) == 0)) {
                return dstu4145_cache_by_onb_curr;
            } else {
                dstu4145_cache_by_onb_curr = dstu4145_cache_by_onb_curr->next;
            }
        }
    }

    return NULL;
}

/* Шукає елемент кешу ECDSA порівнянням усіх параметрів кривої; NULL, якщо не знайдено. */
static EcdsaCache *ecdsa_cache_get_element( const ByteArray *p, const ByteArray *a, const ByteArray *b,
        const ByteArray *q, const ByteArray *px, const ByteArray *py)
{
    if (ecdsa_cache) {
        EcdsaCache *ecdsa_cache_curr = ecdsa_cache;
        while (ecdsa_cache_curr != NULL) {
            if ((ba_cmp(ecdsa_cache_curr->p, p) == 0)
                    && (ba_cmp(ecdsa_cache_curr->a, a) == 0)
                    && (ba_cmp(ecdsa_cache_curr->b, b) == 0)
                    && (ba_cmp(ecdsa_cache_curr->q, q) == 0)
                    && (ba_cmp(ecdsa_cache_curr->px, px) == 0)
                    && (ba_cmp(ecdsa_cache_curr->py, py) == 0)) {
                return ecdsa_cache_curr;
            } else {
                ecdsa_cache_curr = ecdsa_cache_curr->next;
            }
        }
    }

    return NULL;
}

/* Звільняє один елемент кешу за params_id разом із контекстом. */
static void dstu4145_cache_id_free(Dstu4145CacheById *dstu4145_cache_by_id_curr)
{
    if (dstu4145_cache_by_id_curr) {
        dstu4145_free(dstu4145_cache_by_id_curr->ctx);
        free(dstu4145_cache_by_id_curr);
    }
}

/*
 * Створює контекст ДСТУ 4145 зі стандартними параметрами, застосовує
 * рівень оптимізації (передобчислення) і додає його в кеш.
 * Повертає RET_CTX_ALREADY_IN_CACHE, якщо такі параметри вже закешовано.
 */
int crypto_cache_add_dstu4145(Dstu4145ParamsId params_id, OptLevelId opt_level)
{
    int ret = RET_OK;
    Dstu4145Ctx *dstu_ctx = NULL;
    Dstu4145CacheById *dstu4145_cache_by_id_curr = NULL;
    Dstu4145CacheById *dstu4145_cache_by_id_new = NULL;

    pthread_mutex_lock(&dstu4145_cache_by_id_mutex);

    dstu4145_cache_by_id_curr = dstu4145_cache_get_element_by_id(params_id);
    if (dstu4145_cache_by_id_curr != NULL) {
        SET_ERROR(RET_CTX_ALREADY_IN_CACHE);
    } else {
        CALLOC_CHECKED(dstu4145_cache_by_id_new, sizeof(Dstu4145CacheById));

        CHECK_NOT_NULL(dstu_ctx = dstu4145_alloc_new(params_id));
        DO(dstu4145_set_opt_level(dstu_ctx, opt_level));

        dstu4145_cache_by_id_new->ctx = dstu_ctx;
        dstu_ctx = NULL;
        dstu4145_cache_by_id_new->params_id = params_id;

        dstu4145_cache_id_append(dstu4145_cache_by_id_new);
        dstu4145_cache_by_id_new = NULL;
    }

cleanup:

    pthread_mutex_unlock(&dstu4145_cache_by_id_mutex);
    dstu4145_cache_id_free(dstu4145_cache_by_id_new);
    dstu4145_free(dstu_ctx);

    return ret;
}

/*
 * Повертає копію кешованого контексту ДСТУ 4145 за params_id.
 * Якщо контексту немає в кеші, а default_opt_level != 0 — спершу створює
 * та кешує його. Повертає NULL, якщо контекст не знайдено й ліниве
 * кешування вимкнено, або в разі помилки.
 */
Dstu4145Ctx *crypto_cache_get_dstu4145(Dstu4145ParamsId params_id)
{
    int ret = RET_OK;
    Dstu4145CacheById *dstu4145_cache_by_id_curr = NULL;
    Dstu4145Ctx *ctx = NULL;

    dstu4145_cache_by_id_curr = dstu4145_cache_get_element_by_id(params_id);
    if (dstu4145_cache_by_id_curr != NULL) {
        CHECK_NOT_NULL(ctx = dstu4145_copy_params_with_alloc(dstu4145_cache_by_id_curr->ctx));
    } else if (default_opt_level != 0) {

        ret = crypto_cache_add_dstu4145(params_id, default_opt_level);
        if (ret != RET_OK && ret != RET_CTX_ALREADY_IN_CACHE) {
            SET_ERROR(ret);
        }

        dstu4145_cache_by_id_curr = dstu4145_cache_get_element_by_id(params_id);
        if (dstu4145_cache_by_id_curr != NULL) {
            CHECK_NOT_NULL(ctx = dstu4145_copy_params_with_alloc(dstu4145_cache_by_id_curr->ctx));
        }
    }

cleanup:

    return ctx;
}

/* Звільняє один елемент кешу параметрів у ПБ разом із контекстом та копіями параметрів. */
static void dstu4145_cache_pb_free(Dstu4145CacheByPb *dstu4145_cache_by_pb_curr)
{
    if (dstu4145_cache_by_pb_curr) {
        free(dstu4145_cache_by_pb_curr->f);
        ba_free(dstu4145_cache_by_pb_curr->b);
        ba_free(dstu4145_cache_by_pb_curr->n);
        ba_free(dstu4145_cache_by_pb_curr->px);
        ba_free(dstu4145_cache_by_pb_curr->py);
        dstu4145_free(dstu4145_cache_by_pb_curr->ctx);
        free(dstu4145_cache_by_pb_curr);
    }
}

/*
 * Створює контекст ДСТУ 4145 з довільними параметрами у ПБ, застосовує
 * рівень оптимізації і додає його в кеш разом із копіями параметрів
 * (вони слугують ключем пошуку).
 * Повертає RET_CTX_ALREADY_IN_CACHE, якщо такі параметри вже закешовано.
 */
int crypto_cache_add_dstu4145_pb(const int *f, size_t f_len, int a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py, OptLevelId opt_level)
{
    int ret = RET_OK;
    Dstu4145Ctx *dstu_ctx = NULL;
    Dstu4145CacheByPb *dstu4145_cache_by_pb_curr = NULL;
    Dstu4145CacheByPb *dstu4145_cache_by_pb_new = NULL;

    pthread_mutex_lock(&dstu4145_cache_by_pb_mutex);

    dstu4145_cache_by_pb_curr = dstu4145_cache_get_element_by_pb(f, f_len, a, b, n, px, py);
    if (dstu4145_cache_by_pb_curr != NULL) {
        SET_ERROR(RET_CTX_ALREADY_IN_CACHE);
    } else {
        CALLOC_CHECKED(dstu4145_cache_by_pb_new, sizeof(Dstu4145CacheByPb));

        CHECK_NOT_NULL(dstu_ctx = dstu4145_alloc_pb_new(f, f_len, a, b, n, px, py));
        DO(dstu4145_set_opt_level(dstu_ctx, opt_level));

        dstu4145_cache_by_pb_new->ctx = dstu_ctx;
        dstu_ctx = NULL;
        CALLOC_CHECKED(dstu4145_cache_by_pb_new->f, f_len * sizeof(int));
        memcpy(dstu4145_cache_by_pb_new->f, f, f_len * sizeof(int));
        dstu4145_cache_by_pb_new->f_len = f_len;
        dstu4145_cache_by_pb_new->a = a;
        CHECK_NOT_NULL(dstu4145_cache_by_pb_new->b = ba_copy_with_alloc(b, 0, 0));
        CHECK_NOT_NULL(dstu4145_cache_by_pb_new->n = ba_copy_with_alloc(n, 0, 0));
        CHECK_NOT_NULL(dstu4145_cache_by_pb_new->px = ba_copy_with_alloc(px, 0, 0));
        CHECK_NOT_NULL(dstu4145_cache_by_pb_new->py = ba_copy_with_alloc(py, 0, 0));

        dstu4145_cache_pb_append(dstu4145_cache_by_pb_new);
        dstu4145_cache_by_pb_new = NULL;
    }

cleanup:

    pthread_mutex_unlock(&dstu4145_cache_by_pb_mutex);
    dstu4145_cache_pb_free(dstu4145_cache_by_pb_new);
    dstu4145_free(dstu_ctx);

    return ret;
}

/*
 * Повертає копію кешованого контексту ДСТУ 4145 за параметрами у ПБ;
 * за потреби (default_opt_level != 0) створює та кешує контекст.
 */
Dstu4145Ctx *crypto_cache_get_dstu4145_pb(const int *f, size_t f_len, int a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py)
{
    int ret = RET_OK;
    Dstu4145CacheByPb *dstu4145_cache_by_pb_curr = NULL;
    Dstu4145Ctx *ctx = NULL;

    dstu4145_cache_by_pb_curr = dstu4145_cache_get_element_by_pb(f, f_len, a, b, n, px, py);
    if (dstu4145_cache_by_pb_curr != NULL) {
        CHECK_NOT_NULL(ctx = dstu4145_copy_params_with_alloc(dstu4145_cache_by_pb_curr->ctx));
    } else if (default_opt_level != 0) {

        DO(crypto_cache_add_dstu4145_pb(f, f_len, a, b, n, px, py, default_opt_level));

        dstu4145_cache_by_pb_curr = dstu4145_cache_get_element_by_pb(f, f_len, a, b, n, px, py);
        if (dstu4145_cache_by_pb_curr != NULL) {
            CHECK_NOT_NULL(ctx = dstu4145_copy_params_with_alloc(dstu4145_cache_by_pb_curr->ctx));
        }
    }

cleanup:

    return ctx;
}

/* Звільняє один елемент кешу параметрів в ОНБ разом із контекстом та копіями параметрів. */
static void dstu4145_cache_onb_free(Dstu4145CacheByOnb *dstu4145_cache_by_onb_curr)
{
    if (dstu4145_cache_by_onb_curr) {
        ba_free(dstu4145_cache_by_onb_curr->b);
        ba_free(dstu4145_cache_by_onb_curr->n);
        ba_free(dstu4145_cache_by_onb_curr->px);
        ba_free(dstu4145_cache_by_onb_curr->py);
        dstu4145_free(dstu4145_cache_by_onb_curr->ctx);
        free(dstu4145_cache_by_onb_curr);
    }
}

/*
 * Створює контекст ДСТУ 4145 з довільними параметрами в ОНБ, застосовує
 * рівень оптимізації і додає його в кеш разом із копіями параметрів.
 * Повертає RET_CTX_ALREADY_IN_CACHE, якщо такі параметри вже закешовано.
 */
int crypto_cache_add_dstu4145_onb(const int m, int a, const ByteArray *b, const ByteArray *n, const ByteArray *px,
        const ByteArray *py, OptLevelId opt_level)
{
    int ret = RET_OK;
    Dstu4145Ctx *dstu_ctx = NULL;
    Dstu4145CacheByOnb *dstu4145_cache_by_onb_curr = NULL;
    Dstu4145CacheByOnb *dstu4145_cache_by_onb_new = NULL;

    pthread_mutex_lock(&dstu4145_cache_by_onb_mutex);

    dstu4145_cache_by_onb_curr = dstu4145_cache_get_element_by_onb(m, a, b, n, px, py);
    if (dstu4145_cache_by_onb_curr != NULL) {
        SET_ERROR(RET_CTX_ALREADY_IN_CACHE);
    } else {
        CALLOC_CHECKED(dstu4145_cache_by_onb_new, sizeof(Dstu4145CacheByOnb));

        CHECK_NOT_NULL(dstu_ctx = dstu4145_alloc_onb_new(m, a, b, n, px, py));
        DO(dstu4145_set_opt_level(dstu_ctx, opt_level));

        dstu4145_cache_by_onb_new->ctx = dstu_ctx;
        dstu_ctx = NULL;
        dstu4145_cache_by_onb_new->m = m;
        dstu4145_cache_by_onb_new->a = a;
        CHECK_NOT_NULL(dstu4145_cache_by_onb_new->b = ba_copy_with_alloc(b, 0, 0));
        CHECK_NOT_NULL(dstu4145_cache_by_onb_new->n = ba_copy_with_alloc(n, 0, 0));
        CHECK_NOT_NULL(dstu4145_cache_by_onb_new->px = ba_copy_with_alloc(px, 0, 0));
        CHECK_NOT_NULL(dstu4145_cache_by_onb_new->py = ba_copy_with_alloc(py, 0, 0));

        dstu4145_cache_onb_append(dstu4145_cache_by_onb_new);
        dstu4145_cache_by_onb_new = NULL;
    }

cleanup:

    pthread_mutex_unlock(&dstu4145_cache_by_onb_mutex);
    dstu4145_cache_onb_free(dstu4145_cache_by_onb_new);
    dstu4145_free(dstu_ctx);

    return ret;
}

/* Звільняє один елемент кешу ECDSA разом із контекстом та копіями параметрів. */
static void ecdsa_cache_free(EcdsaCache *ecdsa_cache_curr)
{
    if (ecdsa_cache_curr) {
        ba_free(ecdsa_cache_curr->p);
        ba_free(ecdsa_cache_curr->a);
        ba_free(ecdsa_cache_curr->b);
        ba_free(ecdsa_cache_curr->q);
        ba_free(ecdsa_cache_curr->px);
        ba_free(ecdsa_cache_curr->py);
        ecdsa_free(ecdsa_cache_curr->ctx);
        free(ecdsa_cache_curr);
    }
}

/*
 * Створює контекст ECDSA із заданими параметрами кривої над простим полем,
 * застосовує рівень оптимізації і додає його в кеш разом із копіями параметрів.
 * Повертає RET_CTX_ALREADY_IN_CACHE, якщо такі параметри вже закешовано.
 */
int crypto_cache_add_ecdsa(const ByteArray *p, const ByteArray *a, const ByteArray *b, const ByteArray *q,
        const ByteArray *px, const ByteArray *py, OptLevelId opt_level)
{
    int ret = RET_OK;
    EcdsaCtx *ecdsa_ctx = NULL;
    EcdsaCache *ecdsa_cache_curr = NULL;
    EcdsaCache *ecdsa_cache_new = NULL;

    pthread_mutex_lock(&ecdsa_cache_mutex);

    ecdsa_cache_curr = ecdsa_cache_get_element(p, a, b, q, px, py);
    if (ecdsa_cache_curr != NULL) {
        SET_ERROR(RET_CTX_ALREADY_IN_CACHE);
    } else {
        CALLOC_CHECKED(ecdsa_cache_new, sizeof(EcdsaCache));

        CHECK_NOT_NULL(ecdsa_ctx = ecdsa_alloc_ext_new(p, a, b, q, px, py));
        DO(ecdsa_set_opt_level(ecdsa_ctx, opt_level));

        ecdsa_cache_new->ctx = ecdsa_ctx;
        ecdsa_ctx = NULL;
        CHECK_NOT_NULL(ecdsa_cache_new->p = ba_copy_with_alloc(p, 0, 0));
        CHECK_NOT_NULL(ecdsa_cache_new->a = ba_copy_with_alloc(a, 0, 0));
        CHECK_NOT_NULL(ecdsa_cache_new->b = ba_copy_with_alloc(b, 0, 0));
        CHECK_NOT_NULL(ecdsa_cache_new->q = ba_copy_with_alloc(q, 0, 0));
        CHECK_NOT_NULL(ecdsa_cache_new->px = ba_copy_with_alloc(px, 0, 0));
        CHECK_NOT_NULL(ecdsa_cache_new->py = ba_copy_with_alloc(py, 0, 0));

        ecdsa_cache_append(ecdsa_cache_new);
        ecdsa_cache_new = NULL;
    }

cleanup:

    pthread_mutex_unlock(&ecdsa_cache_mutex);
    ecdsa_cache_free(ecdsa_cache_new);
    ecdsa_free(ecdsa_ctx);

    return ret;
}

/*
 * Повертає копію кешованого контексту ДСТУ 4145 за параметрами в ОНБ;
 * за потреби (default_opt_level != 0) створює та кешує контекст.
 */
Dstu4145Ctx *crypto_cache_get_dstu4145_onb(const int m, int a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py)
{
    int ret = RET_OK;
    Dstu4145CacheByOnb *dstu4145_cache_by_onb_curr = NULL;
    Dstu4145Ctx *ctx = NULL;

    dstu4145_cache_by_onb_curr = dstu4145_cache_get_element_by_onb(m, a, b, n, px, py);
    if (dstu4145_cache_by_onb_curr != NULL) {
        CHECK_NOT_NULL(ctx = dstu4145_copy_params_with_alloc(dstu4145_cache_by_onb_curr->ctx));
    } else if (default_opt_level != 0) {

        DO(crypto_cache_add_dstu4145_onb(m, a, b, n, px, py, default_opt_level));

        dstu4145_cache_by_onb_curr = dstu4145_cache_get_element_by_onb(m, a, b, n, px, py);
        if (dstu4145_cache_by_onb_curr != NULL) {
            CHECK_NOT_NULL(ctx = dstu4145_copy_params_with_alloc(dstu4145_cache_by_onb_curr->ctx));
        }
    }
cleanup:

    return ctx;
}

/*
 * Повертає копію кешованого контексту ECDSA за параметрами кривої;
 * за потреби (default_opt_level != 0) створює та кешує контекст.
 */
EcdsaCtx *crypto_cache_get_ecdsa(const ByteArray *p, const ByteArray *a, const ByteArray *b, const ByteArray *q,
        const ByteArray *px, const ByteArray *py)
{
    int ret = RET_OK;
    EcdsaCache *ecdsa_cache_curr = NULL;
    EcdsaCtx *ctx = NULL;

    ecdsa_cache_curr = ecdsa_cache_get_element(p, a, b, q, px, py);
    if (ecdsa_cache_curr != NULL) {
        CHECK_NOT_NULL(ctx = ecdsa_copy_params_with_alloc(ecdsa_cache_curr->ctx));
    } else if (default_opt_level != 0) {

        DO(crypto_cache_add_ecdsa(p, a, b, q, px, py, default_opt_level));

        ecdsa_cache_curr = ecdsa_cache_get_element(p, a, b, q, px, py);
        if (ecdsa_cache_curr != NULL) {
            CHECK_NOT_NULL(ctx = ecdsa_copy_params_with_alloc(ecdsa_cache_curr->ctx));
        }
    }

cleanup:

    return ctx;
}

/*
 * Встановлює рівень оптимізації за замовчуванням, вмикаючи ліниве
 * кешування контекстів при першому запиті.
 * opt_level пакує чотири 4-бітові поля (від старших до молодших бітів):
 * comb- та window-рівень для формування підпису, comb- та window-рівень
 * для перевірки. Для кожної пари можна задати лише один метод
 * передобчислень, а window-рівень має бути непарним.
 */
int crypto_cache_add_any_new(OptLevelId opt_level)
{
    int ret = RET_OK;

    int sign_comb_opt_level = (opt_level >> 12) & 0x0f;
    int sign_win_opt_level = (opt_level >> 8) & 0x0f;
    int verify_comb_opt_level = (opt_level >> 4) & 0x0f;
    int verify_win_opt_level = opt_level & 0x0f;

    CHECK_PARAM(sign_comb_opt_level == 0 || sign_win_opt_level == 0);
    CHECK_PARAM(sign_win_opt_level == 0 || (sign_win_opt_level & 1) == 1);
    CHECK_PARAM(verify_comb_opt_level == 0 || verify_win_opt_level == 0);
    CHECK_PARAM(verify_win_opt_level == 0 || (verify_win_opt_level & 1) == 1);

    default_opt_level = opt_level;

cleanup:

    return ret;
}

/* Звільняє весь список кешу за params_id. */
static void dstu4145_cache_id_list_free(void)
{
    if (dstu4145_cache_by_id) {
        Dstu4145CacheById *dstu4145_cache_by_id_next = dstu4145_cache_by_id;
        dstu4145_cache_by_id = NULL;
        Dstu4145CacheById *dstu4145_cache_by_id_curr;

        while (dstu4145_cache_by_id_next != NULL) {
            dstu4145_cache_by_id_curr = dstu4145_cache_by_id_next;
            dstu4145_cache_by_id_next = dstu4145_cache_by_id_curr->next;
            dstu4145_cache_id_free(dstu4145_cache_by_id_curr);
        }
    }
}

/* Звільняє весь список кешу параметрів у ПБ. */
static void dstu4145_cache_pb_list_free(void)
{
    if (dstu4145_cache_by_pb) {
        Dstu4145CacheByPb *dstu4145_cache_by_pb_next = dstu4145_cache_by_pb;
        dstu4145_cache_by_pb = NULL;
        Dstu4145CacheByPb *dstu4145_cache_by_pb_curr;

        while (dstu4145_cache_by_pb_next != NULL) {
            dstu4145_cache_by_pb_curr = dstu4145_cache_by_pb_next;
            dstu4145_cache_by_pb_next = dstu4145_cache_by_pb_curr->next;
            dstu4145_cache_pb_free(dstu4145_cache_by_pb_curr);
        }
    }
}

/* Звільняє весь список кешу параметрів в ОНБ. */
static void dstu4145_cache_onb_list_free(void)
{
    if (dstu4145_cache_by_onb) {
        Dstu4145CacheByOnb *dstu4145_cache_by_onb_next = dstu4145_cache_by_onb;
        dstu4145_cache_by_onb = NULL;
        Dstu4145CacheByOnb *dstu4145_cache_by_onb_curr;

        while (dstu4145_cache_by_onb_next != NULL) {
            dstu4145_cache_by_onb_curr = dstu4145_cache_by_onb_next;
            dstu4145_cache_by_onb_next = dstu4145_cache_by_onb_curr->next;
            dstu4145_cache_onb_free(dstu4145_cache_by_onb_curr);
        }
    }
}

/* Звільняє весь список кешу ECDSA. */
static void ecdsa_cache_list_free(void)
{
    if (ecdsa_cache) {
        EcdsaCache *ecdsa_cache_next = ecdsa_cache;
        ecdsa_cache = NULL;
        EcdsaCache *ecdsa_cache_curr;

        while (ecdsa_cache_next != NULL) {
            ecdsa_cache_curr = ecdsa_cache_next;
            ecdsa_cache_next = ecdsa_cache_curr->next;
            ecdsa_cache_free(ecdsa_cache_curr);
        }
    }
}

/*
 * Звільняє всі списки кешу. Захоплює всі м'ютекси та витримує секундну
 * паузу — грубий захист від потоків, які саме виконують пошук у кеші
 * без блокування.
 */
void crypto_cache_free(void)
{
    pthread_mutex_lock(&dstu4145_cache_by_id_mutex);
    pthread_mutex_lock(&dstu4145_cache_by_pb_mutex);
    pthread_mutex_lock(&dstu4145_cache_by_onb_mutex);
    pthread_mutex_lock(&ecdsa_cache_mutex);

#if defined(_WIN32)
    Sleep(1000);
#else
    sleep(1);
#endif

    dstu4145_cache_id_list_free();
    dstu4145_cache_pb_list_free();
    dstu4145_cache_onb_list_free();
    ecdsa_cache_list_free();

    pthread_mutex_unlock(&dstu4145_cache_by_id_mutex);
    pthread_mutex_unlock(&dstu4145_cache_by_pb_mutex);
    pthread_mutex_unlock(&dstu4145_cache_by_onb_mutex);
    pthread_mutex_unlock(&ecdsa_cache_mutex);
}
