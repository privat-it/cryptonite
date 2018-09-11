/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "math_ec_point_internal.h"
#include "macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/math_ec_point_internal.c"

ECPoint *ec_point_alloc(size_t len)
{
    int ret = RET_OK;
    ECPoint *p = NULL;

    CALLOC_CHECKED(p, sizeof(ECPoint));

    CHECK_NOT_NULL(p->x = wa_alloc_with_zero(len));
    CHECK_NOT_NULL(p->y = wa_alloc_with_zero(len));
    CHECK_NOT_NULL(p->z = wa_alloc_with_zero(len));

    return p;

cleanup:

    ec_point_free(p);

    return NULL;
}

static void ec_point_init(ECPoint *p, const WordArray *px, const WordArray *py, const WordArray *pz)
{
    int ret = RET_OK;

    if (p != NULL) {
        CHECK_NOT_NULL(p->x = wa_copy_with_alloc(px));
        CHECK_NOT_NULL(p->y = wa_copy_with_alloc(py));
        p->z = (pz != NULL) ? wa_copy_with_alloc(pz) : wa_alloc_with_one(px->len);
        CHECK_NOT_NULL(p->z);
        return;
    }
cleanup:
    return;
}

ECPoint *ec_point_aff_alloc(const WordArray *px, const WordArray *py)
{
    ECPoint *p = NULL;
    int ret = RET_OK;

    if (px != NULL && py != NULL) {
        CALLOC_CHECKED(p, sizeof(ECPoint));
        ec_point_init(p, px, py, NULL);
    }

cleanup:

    return p;
}

ECPoint *ec_point_proj_alloc(const WordArray *px, const WordArray *py, const WordArray *pz)
{
    ECPoint *p = NULL;
    int ret = RET_OK;

    if (px != NULL && py != NULL && pz != NULL) {
        CALLOC_CHECKED(p, sizeof(ECPoint));
        ec_point_init(p, px, py, pz);
    }

cleanup:

    return p;
}

void ec_point_zero(ECPoint *p)
{
    if (p != NULL) {
        wa_zero(p->x);
        wa_zero(p->y);
        wa_one(p->z);
    }
}

void ec_point_copy(const ECPoint *a, ECPoint *out)
{
    int ret = RET_OK;

    if (a != NULL && out != NULL) {
        DO(wa_copy(a->x, out->x));
        DO(wa_copy(a->y, out->y));
        DO(wa_copy(a->z, out->z));
    }

cleanup:

    return;
}

ECPoint *ec_point_copy_with_alloc(const ECPoint *a)
{
    ECPoint *out = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(out, sizeof(ECPoint));

    CHECK_NOT_NULL(out->x = wa_copy_with_alloc(a->x));
    CHECK_NOT_NULL(out->y = wa_copy_with_alloc(a->y));
    CHECK_NOT_NULL(out->z = wa_copy_with_alloc(a->z));

    return out;

cleanup:

    ec_point_free(out);

    return NULL;
}

void ec_point_free(ECPoint *p)
{
    if (p != NULL) {
        wa_free(p->x);
        wa_free(p->y);
        wa_free(p->z);
        free(p);
    }
}
