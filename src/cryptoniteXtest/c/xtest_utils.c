/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#ifdef __linux__
#include <unistd.h>
#endif

#include "xtest_utils.h"

#include "byte_utils_internal.h"
#include "byte_array.h"

XtestSt* rnd_generate(size_t size_mode)
{
    srand((unsigned int) time(NULL));
    size_t i;

    XtestSt *ctx = (XtestSt*)malloc(sizeof (XtestSt));
    ctx->data = (uint8_t*)malloc(size_mode);
    for (i = 0; i < size_mode; i++) {
        ctx->data[i] = rand() & 0xFF;
    }

    ctx->data_ba = ba_alloc_from_uint8(ctx->data, size_mode);

    return ctx;
}

void rnd_data_free(XtestSt *ctx)
{
    free(ctx->data);
    ba_free(ctx->data_ba);
    free(ctx);
    ctx = NULL;
}

void SHA_generete_data(XtestSt *ctx)
{
    srand((unsigned int) time(NULL));
    size_t i, j;

    for (j = 0; j < 5; j++) {
        for (i = 0; i < 64; i++) {
            ctx->CipherType.SHA.keys[j][i] = rand() & 0xFF;
        }
    }

    ctx->CipherType.SHA.key_160_ba = ba_alloc_from_uint8((const uint8_t*) &ctx->CipherType.SHA.keys[0], 20);
    ctx->CipherType.SHA.key_224_ba = ba_alloc_from_uint8((const uint8_t*) &ctx->CipherType.SHA.keys[1], 28);
    ctx->CipherType.SHA.key_256_ba = ba_alloc_from_uint8((const uint8_t*) &ctx->CipherType.SHA.keys[2], 32);
    ctx->CipherType.SHA.key_384_ba = ba_alloc_from_uint8((const uint8_t*) &ctx->CipherType.SHA.keys[3], 48);
    ctx->CipherType.SHA.key_512_ba = ba_alloc_from_uint8((const uint8_t*) &ctx->CipherType.SHA.keys[4], 64);
    ctx->alg_type = SHA_HASH;

}

void DES_generete_data(XtestSt *ctx)
{
    srand((unsigned int) time(NULL));
    int i;

    for (i = 0; i < 8; i++) {
        ctx->CipherType.DES.iv[i] = rand() & 0xFF;
    }

    for (i = sizeof (ctx->CipherType.DES.keys) - 1; i >= 0; i--) {
        ctx->CipherType.DES.keys[i] = rand() & 0xFF;
    }

    ctx->CipherType.DES.key_ba = ba_alloc_from_uint8((const uint8_t*) ctx->CipherType.DES.keys, sizeof (ctx->CipherType.DES.keys));
    ctx->CipherType.DES.iv_ba = ba_alloc_from_uint8(ctx->CipherType.DES.iv, 8);
    ctx->alg_type = DES;

    DES_set_key((DES_cblock*) ctx->CipherType.DES.keys, &ctx->CipherType.DES.k1);
    DES_set_key((DES_cblock*) & ctx->CipherType.DES.keys[8], &ctx->CipherType.DES.k2);
    DES_set_key((DES_cblock*) & ctx->CipherType.DES.keys[16], &ctx->CipherType.DES.k3);
}

void add_to_loop(ThreadSt *arg, ByteArray *data_ba, uint8_t *data, int gcrypt_mod)
{
    size_t i = 0;
    size_t data_len;
    data_len = ba_get_len(data_ba);
    for (i = 0; i < THREADS_NUM; i++) {
        arg[i].data = data;
        arg[i].data_ba = data_ba;
        arg[i].time = 0;
        arg[i].algo = gcrypt_mod;
        if (data_len > MB) {
            arg[i].loop_num = 1;
        } else {
            arg[i].loop_num = 100000 >> (data_len >> 8);
        }
        arg[i].res_cryptonite = NULL;
        arg[i].res_ossl = NULL;
        arg[i].res_gcrypt = NULL;
    }
}

void thread_st_add(ThreadHelper *ctx, ThreadSt *thrd_data, XtestSt *cip_data)
{
    size_t i = 0;
    for (i = 0; i < THREADS_NUM; i++) {
        ctx[i].cipher_data = cip_data;
        ctx[i].thread_data = (ThreadSt*)malloc(sizeof (ThreadSt));
        ctx[i].thread_data->res_cryptonite = NULL;
        ctx[i].thread_data->res_ossl = NULL;
        ctx[i].thread_data->res_gcrypt = NULL;
        ctx[i].thread_data->loop_num = thrd_data->loop_num;
        ctx[i].thread_data->data_ba = thrd_data->data_ba;
        ctx[i].thread_data->data = thrd_data->data;
    }
}

void thread_free(ThreadHelper *ctx)
{
    size_t i = 0;
    for (i = 0; i < THREADS_NUM; i++) {
        BA_FREE(ctx[i].thread_data->res_ossl, ctx[i].thread_data->res_gcrypt, ctx[i].thread_data->res_cryptonite);
    }
}

void free_loop(ThreadSt *arg)
{
    size_t i = 0;
    for (i = 0; i < THREADS_NUM; i++) {
        BA_FREE(arg[i].res_ossl, arg[i].res_gcrypt, arg[i].res_cryptonite);
    }
}

void AES_generete_data(XtestSt *ctx)
{
    size_t i, j, k = 16;

    memset(ctx->CipherType.AES.keys, 0, 96);

    for (j = 0; j < 3; j++, k += 8) {
        for (i = 0; i < k; i++) {
            ctx->CipherType.AES.keys[j][i] = rand() & 0xFF;
        }
    }

    ctx->CipherType.AES.key_128_ba = ba_alloc_from_uint8((const uint8_t*) &ctx->CipherType.AES.keys[0], 16);
    ctx->CipherType.AES.key_192_ba = ba_alloc_from_uint8((const uint8_t*) &ctx->CipherType.AES.keys[1], 24);
    ctx->CipherType.AES.key_256_ba = ba_alloc_from_uint8((const uint8_t*) &ctx->CipherType.AES.keys[2], 32);

    AES_set_encrypt_key((const uint8_t*) &ctx->CipherType.AES.keys[0], 128, &ctx->CipherType.AES.key_ossl[0]);
    AES_set_encrypt_key((const uint8_t*) &ctx->CipherType.AES.keys[1], 192, &ctx->CipherType.AES.key_ossl[1]);
    AES_set_encrypt_key((const uint8_t*) &ctx->CipherType.AES.keys[2], 256, &ctx->CipherType.AES.key_ossl[2]);

    ctx->alg_type = AES;
}

void DSTU_generete_data(XtestSt *ctx)
{
    size_t i;

    for (i = 0; i < 64; i++) {
        ctx->CipherType.DSTU.key_data[i] = rand() & 0xFF;
    }

    ctx->CipherType.DSTU.key_128_ba = ba_alloc_from_uint8(ctx->CipherType.DSTU.key_data,  16);
    ctx->CipherType.DSTU.key_256_ba = ba_alloc_from_uint8(ctx->CipherType.DSTU.key_data,  32);
    ctx->CipherType.DSTU.key_512_ba = ba_alloc_from_uint8(ctx->CipherType.DSTU.key_data,  64);
    ctx->CipherType.DSTU.iv_128_ba = ba_alloc_from_uint8(ctx->CipherType.DSTU.key_data,  16);
    ctx->CipherType.DSTU.iv_256_ba = ba_alloc_from_uint8(ctx->CipherType.DSTU.key_data,  32);
    ctx->CipherType.DSTU.iv_512_ba = ba_alloc_from_uint8(ctx->CipherType.DSTU.key_data,  64);

    ctx->alg_type = DSTU;
}

void xtest_alg_free(XtestSt *ctx)
{
    switch (ctx->alg_type) {
    case AES:
        BA_FREE(ctx->CipherType.AES.key_128_ba,
                ctx->CipherType.AES.key_192_ba,
                ctx->CipherType.AES.key_256_ba);
        return;
    case DES:
        BA_FREE(ctx->CipherType.DES.iv_ba, ctx->CipherType.DES.key_ba);
        return;
    case SHA_HASH:
        BA_FREE(ctx->CipherType.SHA.key_160_ba,
                ctx->CipherType.SHA.key_224_ba,
                ctx->CipherType.SHA.key_256_ba,
                ctx->CipherType.SHA.key_384_ba,
                ctx->CipherType.SHA.key_512_ba);
        return;
    case DSTU:
        BA_FREE(ctx->CipherType.DSTU.iv_128_ba,
                        ctx->CipherType.DSTU.iv_256_ba,
                        ctx->CipherType.DSTU.iv_512_ba,
                        ctx->CipherType.DSTU.key_128_ba,
                        ctx->CipherType.DSTU.key_256_ba,
                        ctx->CipherType.DSTU.key_512_ba);
    case RIPEMD_HASH:
        return;
    default:
        return;
    }
}

void thrd_num_retrieve(void)
{
#ifdef _WIN32
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    THREADS_NUM = sysinfo.dwNumberOfProcessors;
#elif __linux__
    THREADS_NUM = (size_t) sysconf(_SC_NPROCESSORS_ONLN);
#elif _osx_
    int mib[4];
    size_t len = sizeof (THREADS_NUM);
    /* set the mib for hw.ncpu */
    mib[0] = CTL_HW;
    mib[1] = HW_AVAILCPU; // alternatively, try HW_NCPU;
    /* get the number of CPUs from the system */
    sysctl(mib, 2, &THREADS_NUM, &len, NULL, 0);
    if (numCPU < 1) {
        mib[1] = HW_NCPU;
        sysctl(mib, 2, &numCPU, &len, NULL, 0);

        if (numCPU < 1) {
            numCPU = 1;
        }
    }
#else
    THREADS_NUM = 2;
#endif
}

static void get_colored(TableBuilder *ctx)
{
    Column *ptr = ctx->column;
    size_t max_ind, min_ind;
    size_t i;
    bool is_skiped = false;

    for (; ptr != NULL;) {
        ptr->color[0] = WHITE;
        min_ind = 0;
        max_ind = 0;
        for (i = 1; i < ctx->arg_num; i++) {
            ptr->color[i] = WHITE;
            if (ptr->time[max_ind] < ptr->time[i]) {
                max_ind = i;
            }
            if (ptr->time[min_ind] == 0) {
                min_ind = i;
                is_skiped = true;
            }
            if (ptr->time[min_ind] > ptr->time[i] && ptr->time[i] != 0) {
                min_ind = i;
            }
        }
        if (ptr->time[min_ind] == ptr->time[max_ind]) {
            ptr->color[max_ind] = WHITE;
            ptr->color[min_ind] = WHITE;
        } else {
            /*Р•СЃР»Рё РµСЃС‚СЊ РїСЂРѕРїСѓС‰РµРЅС‹Р№ РµР»РµР�?РµРЅС‚, С‚РѕРіРґР° РёСЃРїРѕР»СЊР·СѓСЋС‚СЃСЏ 2 С†РІРµС‚Р°, Р·РµР»РµРЅС‹Р№ Рё Р±РµР»С‹Р№, С‚Р°Рє РєР°Рє РєСЂР°СЃРЅС‹Р�? РїРѕРґРєСЂР°С€РёРІР°РµС‚СЃСЏ SKIPED.*/
            ptr->color[min_ind] = RED;
            ptr->color[max_ind] = GREEN;
        }
        if (is_skiped == true) {
            for (i = 0; i < ctx->arg_num; i++) {
                if (ptr->color[i] == RED) {
                    ptr->color[i] = WHITE;
                }
            }
        }
        is_skiped = false;
        ptr = ptr->next;

    }
}

void xtest_table_print(TableBuilder *ctx)
{
    uint8_t buf[SIZE_STR];
    size_t tmp;
    size_t str_len;
    size_t column_len;
    size_t i = 0, j = 0, k = 0;
    Column *swap = NULL;
    size_t dot_shift = 14;

    switch(ctx->arg_num) {
        case 2:
            column_len = SIZE_STR / (ctx->arg_num + 2);
            break;
        case 3:
            column_len = SIZE_STR / (ctx->arg_num + 1);
            break;
        default:
            column_len = 0;
    }

#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;
#endif
    get_colored(ctx);

    memset(buf, 0, SIZE_STR);

    if (ctx->lib_name != NULL) {
        PR("%s", WSPACE_STRING80 + (SIZE_STR - column_len));
        if (ctx->arg_num == 2) {
            PR("                    ");
        }
        for (i = 0; i < ctx->arg_num; i++) {
            str_len = strlen(ctx->lib_name[i]);
            tmp = ((column_len - str_len) / 2);
            PR("%s", WSPACE_STRING80 + (SIZE_STR - (str_len % 2 == 0 ? tmp : tmp + 1)));
            PR("%s", WSPACE_STRING80 + (SIZE_STR - tmp));
            if (!memcmp(ctx->lib_name[i], "Cryptonite", strlen(ctx->lib_name[i]))) {
                COLOR_GREEN;
            }
            PR("%s", ctx->lib_name[i]);
            COLOR_RESET;
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
        if (ctx->arg_num == 2) {
            PR("%s",  DOT_STRING80 + (SIZE_STR - (str_len > 20 ? 20 - (str_len - 20) : 20)));
        }
        for (j = 0; j < ctx->arg_num; j++) { 
            if (ctx->column->is_failed[j] == true) {
                PR("%s", DOT_STRING80 + (SIZE_STR - dot_shift));
                COLOR_RED;
                PR("FAILED");
                goto end_loop;
            }
            tmp = (size_t) ctx->column->time[j];
            for (k = 0; tmp != 0; k++) {
                tmp /= 10;
            }
            tmp = (size_t) (column_len - k - 9) / 2;
            PR("%s", DOT_STRING80 + (SIZE_STR - tmp - 1) + ((k % 2 == 0) ? 0 : 1));
            PR("%s", DOT_STRING80 + (SIZE_STR - tmp - 1));
            switch (ctx->column->color[j]) {
            case 0:
                COLOR_GREEN;
                break;
            case 1:
                COLOR_RED;
                break;
            case 2:
                COLOR_RESET;
                break;
            default:
                COLOR_RESET;
            }
            if (ctx->column->time[j] == 0) {
                PR("..");
                COLOR_RED;
                PR("SKIPED");
                COLOR_RESET;
            } else {
                PR("%.1f%s", ctx->column->time[j], ctx->default_speed_value);
            }
        end_loop:
            COLOR_RESET;
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

/* for gcrypt 32bit*/
#ifdef __APPLE__
#ifndef __bswapdi2

uint64_t __bswapdi2(uint64_t x)
{
    return __builtin_bswap64(x);
}

#endif
#endif
