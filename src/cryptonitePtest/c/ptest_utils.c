/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <string.h>

#include "test_utils.h"
#include "pthread_internal.h"
static pthread_t tid[8];

void ptest_table_print(TableBuilder *ctx)
{
    uint8_t buf[SIZE_STR];
    size_t tmp;
    size_t str_len;
    size_t column_len;
    size_t i = 0, j = 0, k = 0;
    Column *swap = NULL;

    column_len = SIZE_STR / (ctx->arg_num + 1);
    memset(buf, 0, SIZE_STR);
    if (ctx->lib_name != NULL) {
        PR("%s", WSPACE_STRING80 + (SIZE_STR - column_len));
        for (i = 0; i < ctx->arg_num; i++) {
            str_len = strlen(ctx->lib_name[i]);
            tmp = ((column_len - str_len) / 2);
            PR("%s", WSPACE_STRING80 + (SIZE_STR - (str_len % 2 == 0 ? tmp : tmp + 1)));
            PR("%s", WSPACE_STRING80 + (SIZE_STR - (tmp % 2 == 0 ? tmp : tmp)));
            PR("%s", ctx->lib_name[i]);
        }
        for (i = 0; i < ctx->arg_num; i++) {
            free(ctx->lib_name[i]);
        }
        free(ctx->lib_name);
        ctx->lib_name = NULL;
        PR("\n");
    }

    memset(buf, 0, SIZE_STR);

    for (i = 0; ctx->column != NULL; i++) {
        str_len = strlen(ctx->column->name);
        PR("%s", ctx->column->name);
        PR("%s", DOT_STRING80 + (SIZE_STR - (column_len - str_len)));
        for (j = 0; j < ctx->arg_num; j++) {
            tmp = (size_t) (ctx->column->time[j] < 1 ? ctx->column->time[j] * 10 : ctx->column->time[j]);
            for (k = 0; tmp != 0; k++) {
                tmp /= 10;
            }

            tmp = (size_t) (column_len - k - 9) / 2;
            PR("%s", DOT_STRING80 + (SIZE_STR - tmp - 1) + ((k % 2 == 0) ? 0 : 1));
            PR("%s", DOT_STRING80 + (SIZE_STR - tmp - 1));

            PR("%.1f%s", ctx->column->time[j], ctx->default_speed_value);
        }
        swap = ctx->column->next;
        free(ctx->column->color);
        free(ctx->column->is_failed);
        free(ctx->column->name);
        free(ctx->column->time);
        free(ctx->column);
        ctx->column = swap;
        PR("\n");
    }
}

typedef struct TableBuilders_st {
    TableBuilder *tb;
} TableBuilders;

void ptest_pthread_generator(void *(*ptest_func)(void *ctx), TableBuilder *table_builder)
{
    size_t i = 0;
    TableBuilders *tbs = malloc(sizeof(TableBuilders) * THREADS_NUM);

    tbs[0].tb = table_builder;
    for (i = 1; i < THREADS_NUM; i++) {
        tbs[i].tb = table_builder_alloc(1);
        add_default_speed_measure(tbs[i].tb, table_builder->default_speed_value);
    }

    for (i = 0; i < THREADS_NUM; i++) {
        pthread_create(&tid[i], NULL, ptest_func, tbs[i].tb);
    }

    for (i = 0; i < THREADS_NUM; i++) {
        pthread_join(tid[i], NULL);
    }

    for (i = 1; i < THREADS_NUM; i++) {
        table_builder->column->time[0] += tbs[i].tb->column->time[0];
    }

    for (i = 1; i < THREADS_NUM; i++) {
        table_builder_free(tbs[i].tb);
    }
    free(tbs);

    ptest_table_print(table_builder);
}
