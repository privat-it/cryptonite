/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_MACROS_INTERNAL_H_
#define CRYPTONITE_MACROS_INTERNAL_H_

#include <stdlib.h>

#include "cryptonite_errors.h"
#include "stacktrace.h"

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define DO(func)                                         \
    {                                                    \
        ret = (func);                                    \
        if (ret != RET_OK) {                             \
            ERROR_ADD(ret);                              \
            goto cleanup;                                \
        }                                                \
    }

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define MALLOC_CHECKED(_buffer, _len)                    \
    {                                                    \
        if (NULL == (_buffer = malloc(_len))) {          \
            ret = RET_MEMORY_ALLOC_ERROR;                \
            ERROR_CREATE(ret);                           \
            goto cleanup;                                \
        }                                                \
    }

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define CALLOC_CHECKED(_buffer, _len)                    \
    {                                                    \
        if (NULL == (_buffer = calloc(1, _len))) {       \
            ret = RET_MEMORY_ALLOC_ERROR;                \
            ERROR_CREATE(ret);                           \
            goto cleanup;                                \
        }                                                \
    }

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define REALLOC_CHECKED(_buffer, _len, _out)             \
    {                                                    \
        void *tmp = NULL;                                \
        if (NULL == (tmp = realloc(_buffer, _len))) {    \
            ret = RET_MEMORY_ALLOC_ERROR;                \
            ERROR_CREATE(ret);                           \
            goto cleanup;                                \
        }                                                \
        _out = tmp;                                      \
    }

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define CHECK_PARAM(_statement)                          \
    {                                                    \
        if (!(_statement)) {                             \
            ret = RET_INVALID_PARAM;                     \
            ERROR_CREATE(ret);                           \
            goto cleanup;                                \
        }                                                \
    }

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define CHECK_NOT_NULL(_buffer)                          \
    {                                                    \
        if (NULL == (_buffer)) {                         \
            ret = RET_INVALID_PARAM;                     \
            ERROR_ADD(ret);                              \
            goto cleanup;                                \
        }                                                \
    }

/**
 * У тілі функції обов'язково повинна бути
 * int ret = RET_OK;
 * ...
 * cleanup:
 * ...
 * return ret;
 */
#define SET_ERROR(_error_code)                           \
        ret = _error_code;                               \
        ERROR_CREATE(ret);                               \
        goto cleanup;

#endif
