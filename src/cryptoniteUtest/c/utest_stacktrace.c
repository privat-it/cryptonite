/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <string.h>

#include "utest.h"
#include "pthread_internal.h"
#include "stacktrace.h"
#include "aes.h"


typedef struct {
    char *key;
    char *iv;
} AesTestCtx;

#define THRD_NUM 4

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/utest_stacktrace.c"

pthread_mutex_t mutex;

static AesTestCtx incorect_data[] = {
    {
        "1213141516171812131415161718",
        "00000000000000000000000000000000"
    },
    {
        "00000000000000000000000000000000",
        "1213141516171812131415161718",
    },
    {
        NULL,
        NULL
    },
    {
        "00000000000000000000000000000000",
        NULL
    }
};

static int err_num[] = { -1, -2, -3, -4, -5};


static int test_func5(int err_num)
{
    ERROR_CREATE(err_num);
    return err_num;
}

static int test_func4(int err_num)
{
    if (err_num == -4) {
        ERROR_CREATE(err_num);
    }  else {
        ERROR_ADD(test_func5(err_num));
    }
    return err_num == -4 ? -2 : -3;
}
static int test_func3(int err_num)
{
    if (err_num == -3) {
        ERROR_CREATE(err_num);
    }  else {
        ERROR_ADD(test_func4(err_num));
    }
    return err_num == -4 ? -5 : -1;
}
static int test_func2(int err_num)
{
    if (err_num == -2) {
        ERROR_CREATE(err_num);
    }  else {
        ERROR_ADD(test_func3(err_num));
    }
    return err_num == -3 ? -4 : -5;
}

static void *test_func1(void *err_num)
{
    pthread_mutex_lock(&mutex);
    const ErrorCtx *error_ctx = NULL;
    int num = ((int *)err_num)[0];

    if (num == -1) {
        ERROR_CREATE(num);
    }  else {
        ERROR_ADD(test_func2(num));
    }

    ASSERT_NOT_NULL(error_ctx = stacktrace_get_last());

    while (error_ctx != NULL) {
        if ((strcmp(error_ctx->file, FILE_MARKER)) || error_ctx->error_code == RET_OK || error_ctx ->line == 0) {
            error_print(error_ctx);
        }
        error_ctx = error_ctx->next;
    }

//    error_ctx_free(error_ctx);

    pthread_mutex_unlock(&mutex);

cleanup:

    return NULL;
}

static void *thread_test_incorect_data_aes(void *void_data)
{
    pthread_mutex_lock(&mutex);
    AesTestCtx *data = (AesTestCtx *)void_data;
    ByteArray *key = ba_alloc_from_le_hex_string(data->key);
    ByteArray *iv = ba_alloc_from_le_hex_string(data->iv);
    ByteArray *cip = NULL;
    int ret = RET_OK;
    AesCtx *ctx = aes_alloc();
    const ErrorCtx *error_ctx = NULL;
ret = aes_init_ctr(ctx, key, iv);

    if (ret != RET_OK) {
        ERROR_ADD(ret);
        error_ctx = stacktrace_get_last();
        if (error_ctx->line == 0 || error_ctx->error_code == 0) {
            ASSERT_RET_OK(RET_INVALID_PARAM);
        }
        ASSERT_NOT_NULL(error_ctx->next);
    }

cleanup:

    aes_free(ctx);
    ba_free(cip);
    ba_free(key);
    ba_free(iv);
    pthread_mutex_unlock(&mutex);
    return NULL;
}

static void utest_aes_incorect_data(void)
{
    pthread_t *pth = NULL;
    size_t i = 0;

    pth = malloc(sizeof (pthread_t) * THRD_NUM);

    for (i = 0; i < THRD_NUM; i++) {
        pthread_create(&pth[i], NULL, thread_test_incorect_data_aes, &incorect_data[i]);
    }

    for (i = 0; i < THRD_NUM; i++) {
        pthread_join(pth[i], NULL);
    }
    free(pth);
}

static void utest_deep_error(void)
{
    pthread_t *pth = NULL;
    size_t i = 0;
    pth = malloc(sizeof (pthread_t) * THRD_NUM);

    for (i = 0; i < THRD_NUM; i++) {
        pthread_create(&pth[i], NULL, test_func1, &err_num[i]);
    }

    for (i = 0; i < THRD_NUM; i++) {
        pthread_join(pth[i], NULL);
    }

    free(pth);
}

void *stacktrace_multithread_func(void *ctx)
{
    ByteArray *ba = ba_alloc_from_le_hex_string(NULL);

    double time = get_time();

    while(((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);


    if (stacktrace_get_last() == NULL) {
        PR("assert: stacktrace_get_last() no error\n");
    }

    stacktrace_free_current();

    if (ba == NULL) {
        return NULL;
    }

    return NULL;
}

void test_stacktrace_copy_error_ctx(void)
{
    const ErrorCtx *error_ctx = NULL;
    ErrorCtx *error_ctx_copy = NULL;
    int num = -5;

    ERROR_ADD(test_func2(num));

    ASSERT_NOT_NULL(error_ctx = stacktrace_get_last());
    ASSERT_NOT_NULL(error_ctx_copy = stacktrace_get_last_with_alloc());

    const ErrorCtx *error_ctx_next = error_ctx;
    const ErrorCtx *error_ctx_copy_next = error_ctx_copy;

    while (error_ctx_next != NULL) {
        ASSERT_TRUE(error_ctx_next->error_code == error_ctx_copy_next->error_code);
        ASSERT_TRUE(error_ctx_next->line == error_ctx_copy_next->line);
        ASSERT_TRUE(strcmp(error_ctx_next->file, error_ctx_copy_next->file) == 0);
        error_ctx_next = error_ctx_next->next;
        error_ctx_copy_next = error_ctx_copy_next->next;
    }

cleanup:

    error_ctx_free(error_ctx_copy);

    pthread_mutex_unlock(&mutex);

}

void test_stacktrace_multithread(void)
{
    pthread_t tid[50] = {0x00};
    int i, count = 0;

    for (i = 0; i < 50; i++) {
        if (pthread_create(&tid[i], NULL, stacktrace_multithread_func, NULL) != 0) {
            break;
        }
    }

    count = i;

    for (i = 0; i < count; i++) {
        pthread_join(tid[i], NULL);
    }

    stacktrace_finalize();
}

void utest_stacktrace(void)
{
    PR("%s\n", __FILE__);

    pthread_mutex_init(&mutex, NULL);
    utest_deep_error();
    utest_aes_incorect_data();
    test_stacktrace_copy_error_ctx();
    pthread_mutex_destroy(&mutex);
    stacktrace_finalize();

    test_stacktrace_multithread();
}
