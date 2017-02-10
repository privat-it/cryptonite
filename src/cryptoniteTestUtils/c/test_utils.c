/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#include <unistd.h>
#endif

#include "test_utils.h"
#include "rs.h"

size_t error_count = 0;
int success_count = 0;
size_t level_num = 0;

char DOT_STRING80[]    = "................................................................................";
char WSPACE_STRING80[] = "                                                                                ";

const char *location_cut(const char *file)
{
    const char *file_ptr = NULL;
    const char cryptonite_text[] = "src";

    size_t len;
    size_t cryptonite_len;
    size_t i;
    cryptonite_len = strlen(cryptonite_text);
    file_ptr = file;
    len = strlen(file);
    for (i = len - 1; i > 0; i--) {
        if (!memcmp(cryptonite_text, &file[i], cryptonite_len)) {
            return file_ptr + i;
        }
    }
    return NULL;
}

bool assert_true_core(bool expression, char *file, int line)
{
    if (!expression) {
        PR("-------------------------------------------------------------------------------\n");
        PR("%s:%i: Assert failed.\n", location_cut(file), line);
        PR("Expected: true\n");
        PR("Actual  : false\n");
        error_count++;
        PR("-------------------------------------------------------------------------------\n");
        return false;
    }

    return true;
}

bool assert_ret_ok_core(int ret, char *file, int line)
{
    if (ret != RET_OK) {
        PR("-------------------------------------------------------------------------------\n");
        PR("%s:%i: Assert failed.\n", location_cut(file), line);
        PR("Expected: RET_OK\n");
        switch (ret) {
        case RET_MEMORY_ALLOC_ERROR:
            PR("Actual  : RET_MEMORY_ALLOC_ERROR\n");
            break;
        case RET_INVALID_PARAM:
            PR("Actual  : RET_INVALID_PARAM\n");
            break;
        case RET_VERIFY_FAILED:
            PR("Actual  : RET_VERIFY_FAILED\n");
            break;
        case RET_CONTEXT_NOT_READY:
            PR("Actual  : RET_CONTEXT_NOT_READY\n");
            break;
        case RET_INVALID_CTX:
            PR("Actual  : RET_INVALID_CTX\n");
            break;
        case RET_DSTU_PRNG_LOOPED:
            PR("Actual  : RET_DSTU_PRNG_LOOPED\n");
            break;
        case RET_INVALID_PUBLIC_KEY:
            PR("Actual  : RET_INVALID_PUBLIC_KEY\n");
            break;
        case RET_INVALID_MODE:
            PR("Actual  : RET_INVALID_MODE\n");
            break;
        case RET_UNSUPPORTED:
            PR("Actual  : RET_UNSUPPORTED\n");
            break;
        default:
            PR("Actual  : UNKNOWN ERROR\n");
            break;
        }
        error_count++;
        PR("-------------------------------------------------------------------------------\n");
        error_print(stacktrace_get_last());
        return false;
    }

    return true;
}

bool assert_ret_core(int exp_ret, int act_ret, char *file, int line)
{
    if (act_ret != exp_ret) {
        PR("-------------------------------------------------------------------------------\n");
        PR("%s:%i: Assert failed.\n", location_cut(file), line);
        PR("Expected: 0x%04x\n", exp_ret);
        PR("Actual  : 0x%04x\n", act_ret);
        error_count++;
        PR("-------------------------------------------------------------------------------\n");
        error_print(stacktrace_get_last());
        return false;
    }

    return true;
}

bool assert_equals_core(const void *expected, const void *actual, size_t size, char *file, int line)
{
    size_t i = 0;
    uint8_t *exp = (uint8_t *) expected;
    uint8_t *act = (uint8_t *) actual;
#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;
#endif
    if (memcmp(expected, actual, size)) {
        PR("-------------------------------------------------------------------------------\n");
        PR("%s:%i: Assert failed.\n", location_cut(file), line);
        PR("Expected bytes:\n");
        for (i = 0; i < size; i++) {
            if (exp[i] != act[i]) {
                COLOR_RED;
            } else {
                COLOR_GREEN;
            }
            PR(" 0x%02x,", exp[i]);
            if ((i + 1) % 16 == 0) {
                PR("\n");
            }
        }
        PR("\n");
        COLOR_RESET;
        PR("Actual bytes: \n");
        for (i = 0; i < size; i++) {
            if (exp[i] != act[i]) {
                COLOR_RED;
            } else {
                COLOR_GREEN;
            }
            PR(" 0x%02x,", act[i]);
            if ((i + 1) % 16 == 0) {
                PR("\n");
            }
        }
        error_count++;

        COLOR_RESET;
        PR("-------------------------------------------------------------------------------\n");

        return false;
    }

    return true;
}

bool assert_equals_str_core(const char *expected, const char *actual, char *file, int line)
{
    if (!expected && !actual) {
        error_count++;
        return false;
    }

    if (strcmp(expected, actual) != 0) {
        PR("-------------------------------------------------------------------------------\n");
        PR("%s:%i: Assert failed.\n", location_cut(file), line);
        PR("Expected : %s\n", expected);
        PR("Actual   : %s\n", actual);
        PR("-------------------------------------------------------------------------------\n");
        error_count++;
        return false;
    }

    return true;
}

bool assert_equals_size_t_core(size_t expected, size_t actual, char *file, int line)
{
    if (expected != actual) {
        PR("-------------------------------------------------------------------------------\n");
        PR("%s:%i: Assert failed.\n", location_cut(file), line);
        PR("Expected size_t: %i\n", (int) expected);
        PR("Actual size_t:   %i\n", (int) actual);
        error_count++;
        PR("-------------------------------------------------------------------------------\n");
        return false;
    }

    return true;
}

bool assert_equals_ptr_core(void *expected, void *actual, char *file, int line)
{
    if (expected != actual) {
        PR("-------------------------------------------------------------------------------\n");
        PR("%s:%i: Assert failed.\n", location_cut(file), line);
        PR("Expected ptr: %p\n", expected);
        PR("Actual ptr:   %p\n", actual);
        error_count++;
        PR("-------------------------------------------------------------------------------\n");
        return false;
    }

    return true;
}

bool assert_equals_ba_core(ByteArray *expected, ByteArray *actual, char *file, int line)
{
    return (expected != NULL && actual != NULL)
            ? (assert_equals_size_t_core(ba_get_len(expected), ba_get_len(actual), file, line))
            && (assert_equals_core(ba_get_buf(expected), ba_get_buf(actual), ba_get_len(actual), file, line))
            : (assert_equals_ptr_core(expected, actual, file, line));
}

bool equals_ba(ByteArray *expected, ByteArray *actual)
{
    if (expected == actual) {
        return true;
    }

    if (expected == NULL || actual == NULL) {
        error_count++;
        return false;
    }

    if (expected->len != actual->len) {
        error_count++;
        return false;
    }

    if (memcmp(expected->buf, actual->buf, actual->len)) {
        error_count++;
        return false;
    }

    return true;
}

bool assert_equals_wa_core(WordArray *expected, WordArray *actual, char *file, int line)
{
    return (expected != NULL && actual != NULL)
            ? assert_equals_size_t_core(expected->len, actual->len, file, line)
            && assert_equals_core(expected->buf, actual->buf, actual->len * sizeof (word_t), file, line)
            : assert_equals_ptr_core(expected, actual, file, line);
}

void ba_free_many(int num, ...)
{
    int i;
    va_list args;

    va_start(args, num);
    for (i = 0; i < num; i++) {
        ba_free(va_arg(args, ByteArray *));
    }
    va_end(args);
}

WordArray *wa_alloc_from_le_hex_string(const char *data)
{
    ByteArray *ba = ba_alloc_from_le_hex_string(data);
    WordArray *wa = wa_alloc_from_ba(ba);
    ba_free(ba);
    return wa;
}

WordArray *wa_alloc_from_be_hex_string(const char *data)
{
    ByteArray *ba = ba_alloc_from_be_hex_string(data);
    WordArray *wa = wa_alloc_from_ba(ba);
    ba_free(ba);
    return wa;
}

void wa_print_be(const WordArray *a)
{
    ByteArray *ba = wa_to_ba(a);
    ba_swap(ba);
    ba_print(stdout, ba);
    ba_free(ba);
}

void add_lib_name(TableBuilder *ctx, char *name)
{
    size_t s_len = strlen(name);
    memcpy(&ctx->lib_name[ctx->lib_num][0], name, s_len);
    ctx->lib_name[ctx->lib_num][s_len] = '\0';
    ctx->lib_num++;
}

void add_error(TableBuilder *ctx, size_t lib_index)
{
    size_t i;
    size_t counter = 0;
    ctx->column->is_failed[lib_index] = true;
    for (i = 0; i < ctx->arg_num; i++) {
        if (ctx->column->is_failed[i] == true && ctx->column->time[i] != 0) {
            counter++;
        }
    }
    if (counter == ctx->arg_num - 1) {
        ctx->column->is_failed[ctx->arg_num - 1] = true;
    }
}

void add_mode_name(TableBuilder *ctx, char *mode)
{
    size_t s_len = strlen(mode);
    Column *tmp = malloc(sizeof (Column));
    tmp->name = malloc(strlen(mode) + 1);
    tmp->time = malloc(ctx->arg_num * sizeof (double) * 2);
    memset(tmp->time, 0, ctx->arg_num * sizeof (double));
    tmp->color = malloc(ctx->arg_num * sizeof (size_t));
    tmp->is_failed = malloc(ctx->arg_num * sizeof (bool));
    memset(tmp->is_failed, false, ctx->arg_num * sizeof (bool));
    memcpy(tmp->name, mode, s_len);
    tmp->name[s_len] = '\0';
    tmp->next = ctx->column;
    ctx->column = tmp;
    ctx->col_num++;
}

double get_time(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (double)(((uint64_t)ft.dwHighDateTime << 32) | (uint64_t)ft.dwLowDateTime);
#elif defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000 * 1000 + (double)tv.tv_usec;
#elif defined(SOLARIS)
    return (double)gethrtime();
#else
    ASSERT(1 == 0);
    return 0;
#endif

}

void add_time(TableBuilder *ctx, double value, size_t lib_index)
{
    double end_time = get_time();

    if (!strcmp(ctx->default_speed_value, "op\\sec")) {
        ctx->column->time[lib_index] = value;
    } else {
        ctx->column->time[lib_index] = ((data_size_byte * LOOP_NUM) >> 20) / ((end_time - value) / DEFAULT_CLOCKS_PS_VALUE);
    }
    ctx->column->color[lib_index] = WHITE;
}

void add_default_speed_measure(TableBuilder *ctx, char *measure_value)
{
    memset(ctx->default_speed_value, 0, sizeof (ctx->default_speed_value));
    strcpy(ctx->default_speed_value, measure_value);
}

TableBuilder *table_builder_alloc(size_t lib_num)
{
    size_t i;
    TableBuilder *ctx = NULL;
    ctx = malloc(sizeof (TableBuilder));
    ctx->mode_num = 0;
    ctx->begin_time_value = 0;
    ctx->col_num = 0;
    ctx->arg_num = lib_num;
    ctx->lib_num = 0;
    ctx->column = NULL;
    ctx->lib_name = malloc(lib_num * sizeof (uint64_t));
    for (i = 0; i < lib_num; i++) {
        ctx->lib_name[i] = malloc(20);
    }

    return ctx;
}

void table_builder_free(TableBuilder *ctx)
{
    for (; ctx->column != NULL;) {
        free(ctx->column->name);
        ctx->column->name = NULL;
        free(ctx->column->time);
        ctx->column->time = NULL;
        free(ctx->column->is_failed);
        ctx->column->is_failed = NULL;
        free(ctx->column->color);
        ctx->column->color = NULL;
        ctx->column = ctx->column->next;
    }
    free(ctx);
}

ByteArray *ba_alloc_from_be_hex_string(const char *data)
{
    ByteArray *out_ba = NULL;
    uint8_t *out = NULL;
    char *data_ext = NULL;
    size_t i;
    char tmp[3] = {0};
    size_t len;

    if (!data) {
        return NULL;
    }

    len = strlen(data);
    if (len % 2 != 0) {
        data_ext = malloc(len + 1);
        data_ext[0] = '0';
        memcpy(data_ext + 1, data, len);
        len++;
    } else {
        data_ext = malloc(len + 1);
        data_ext = strcpy(data_ext, data);
        data_ext[len] = '\0';
    }

    out = malloc(len / 2);

    for (i = 0; i < len / 2; i++) {
        memcpy(tmp, data_ext + 2 * i, 2);
        out[len / 2 - 1 - i] = (uint8_t) strtol(tmp, NULL, 16);
    }

    out_ba = ba_alloc_from_uint8(out, len / 2);

    free(data_ext);
    free(out);

    return out_ba;
}

int read_from_file(const char *file, unsigned char **buffer, size_t *buffer_size)
{
    FILE *p_file;
    size_t l_size;
    size_t result;

    p_file = fopen(file, "rb");
    if (!p_file) {
        return -1;
    }

    fseek(p_file, 0, SEEK_END);
    l_size = ftell(p_file);
    rewind(p_file);

    if (l_size == (size_t) - 1L) {
        fclose(p_file);
        return -1;
    }

    *buffer = calloc(1, sizeof(unsigned char) * l_size);
    if (*buffer == NULL) {
        fclose(p_file);
        return -1;
    }

    result = fread(*buffer, 1, l_size, p_file);
    if (result != l_size) {
        free(*buffer);
        fclose(p_file);
        return -1;
    }

    fclose(p_file);

    *buffer_size = l_size;

    return RET_OK;
}

void error_print(const ErrorCtx *ctx)
{
    const ErrorCtx *step = NULL;
    const char arr[] = "--------------------------------------------------------------------------------";
    PR("%s\n", arr);
    PR("| Stacktrace:\n");
    if (ctx) {
        step = ctx;
        do {
            PR("|%s:%u:, ERROR: 0x%x\n",
                    step->file,
                    (unsigned int)step->line,
                    step->error_code);
            step = step->next;
        } while (step != NULL);
    }
    PR("%s\n", arr);
}

PrngCtx *test_utils_get_prng(void)
{
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(40);

    if (rs_std_next_bytes(seed) != RET_OK) {
        ba_free(seed);
        return NULL;
    }

    prng = prng_alloc(PRNG_MODE_DEFAULT, seed);
    ba_free(seed);

    return prng;
}
