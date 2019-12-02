/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "math_ec_precomp_internal.h"
#include "math_int_internal.h"
#include "macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/math_ec_precomp_internal.c"

EcPrecomp *ec_copy_precomp_with_alloc(EcPrecomp *precomp)
{
    int i, ret = RET_OK;
    EcPrecomp *precomp_copy = NULL;

    if (precomp == NULL) {
        return NULL;
    }

    CALLOC_CHECKED(precomp_copy, sizeof(EcPrecomp));
    precomp_copy->type = precomp->type;
    switch (precomp->type) {
        case EC_PRECOMP_TYPE_COMB:
        CALLOC_CHECKED(precomp_copy->ctx.comb, sizeof(EcPrecompComb));
            precomp_copy->ctx.comb->comb_width = precomp->ctx.comb->comb_width;

            if (precomp->ctx.comb->precomp != NULL) {
                int comb_len = (1 << precomp->ctx.comb->comb_width) - 1;

                CALLOC_CHECKED(precomp_copy->ctx.comb->precomp, comb_len * sizeof(ECPoint *));

                for (i = 0; i < comb_len; i++) {
                    CHECK_NOT_NULL(precomp_copy->ctx.comb->precomp[i] = ec_point_copy_with_alloc(precomp->ctx.comb->precomp[i]));
                }
            }
            break;
        case EC_PRECOMP_TYPE_WIN:
        CALLOC_CHECKED(precomp_copy->ctx.win, sizeof(EcPrecompWin));

            precomp_copy->ctx.win->win_width = precomp->ctx.win->win_width;
            precomp_copy->ctx.win->precomp_len = precomp->ctx.win->precomp_len;

            if (precomp->ctx.win->precomp != NULL) {
                CALLOC_CHECKED(precomp_copy->ctx.win->precomp, precomp->ctx.win->precomp_len * sizeof(ECPoint *));

                for (i = 0; i < precomp->ctx.win->precomp_len; i++) {
                    CHECK_NOT_NULL(precomp_copy->ctx.win->precomp[i] = ec_point_copy_with_alloc(precomp->ctx.win->precomp[i]));
                }
            }
            break;
        default:
            SET_ERROR(RET_INVALID_CTX);
    }

    return precomp_copy;

cleanup:

    ec_precomp_free(precomp_copy);

    return NULL;
}

void ec_precomp_free(EcPrecomp *precomp)
{
    int i;

    if (precomp != NULL) {
        if (precomp->type == EC_PRECOMP_TYPE_COMB) {
            if (precomp->ctx.comb->precomp != NULL) {
                for (i = 0; i < (1 << precomp->ctx.comb->comb_width) - 1; i++) {
                    ec_point_free(precomp->ctx.comb->precomp[i]);
                }
                free(precomp->ctx.comb->precomp);
            }
            free(precomp->ctx.comb);
        } else if (precomp->type == EC_PRECOMP_TYPE_WIN) {
            if (precomp->ctx.win->precomp != NULL) {
                for (i = 0; i < precomp->ctx.win->precomp_len; i++) {
                    ec_point_free(precomp->ctx.win->precomp[i]);
                }
                free(precomp->ctx.win->precomp);
            }
            free(precomp->ctx.win);
        }
        free(precomp);
    }
}
