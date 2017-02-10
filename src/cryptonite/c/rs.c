/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <time.h>
#include <string.h>

#ifdef _WIN32
#   include <windows.h>
#   if !defined(_WIN32_WCE)
#       include <wincrypt.h>
#   endif
#else
#   include <sys/time.h>
#endif

#include "rs.h"
#include "word_internal.h"
#include "math_int_internal.h"
#include "macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/rs.c"

/** Размер области памяти, используемой ГСЧ. */
#ifdef X86
# define MEM_BUF_SIZE (16 * 1024 * 1024)
#else
# define MEM_BUF_SIZE (80 * 1024 * 1024)
#endif

/** Возвращает i-тый бит из потока stream, представленного 8-ми битными словами. */
#define GET_BIT(stream, i) (((stream)[(i) >> 3] >> ((i) & 7)) & 1)

/** Устанавливает i-тый бит в потоке stream, представленном 8-ми битными словами. */
#define SET_BIT(stream, i, bit) (stream)[(i) >> 3] = ((stream)[(i) >> 3] & ~(1 << ((i) & 7))) | ((bit) << ((i) & 7))

/** Длина массива смещений off_buf. */
#define OFF_BUF_LEN     512

/** Начальный размер выборки, полученной от внутреннего источника случайности,
  * которая подается на вход операции устранения смещения.
  * Значение экспериментально рассчитано для x86 так, что после применения процедуры
  * unbias к выборке размера INTERNAL_RS_SAMPLE_LEN, выходная
  * последовательность имеет размер достаточный для инициализации ГПСЧ. */
#define INTERNAL_RS_SAMPLE_LEN 200

/** Контекст генератора. */
typedef struct {
    /* Указатель на область памяти, которая используется функцией шума. */
    uint32_t *mem_buf;
    /* Массив смещений, по которым выполняется чтение оперативной памяти. */
    unsigned int off_buf[OFF_BUF_LEN];
    /* Смещение, начиная с которого заполняется новый массив смещений. */
    unsigned int off;
    /* Чтобы компилятор не выкидывал код. */
    int sum;
} mem_ctx_t;

/**
 * Заполняет буфер случайными байтами.
 *
 * �?спользуемые источники случайности:
 *  - для UNIX используется устройство /dev/urandom;
 *  - для Windows, используется Microsoft CryptoAPI.
 *
 * @param rnd буфер, в котором будут размещены случайные байты
 * @param size размер буфера в байтах
 *
 * @return код ошибки
 */
static int next_bytes_from_os_rng(void *rnd, size_t size)
{
    uint8_t *rnd8 = (uint8_t *)rnd;
    uint8_t *buf = NULL;
    size_t i;
    int ret = RET_OK;

    memset(rnd, 0, size);

    MALLOC_CHECKED(buf, size);

#if defined(_WIN32) && !defined(_WIN32_WCE)
    /* Пытаемся использовать CryptGenRandom */
    while (1) {
        HCRYPTPROV hProv;

        if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == 0) {
            break;
        }

        if (CryptGenRandom(hProv, (DWORD)size, (BYTE *)buf) == TRUE) {
            for (i = 0; i < size; i++) {
                rnd8[i] ^= buf[i];
            }
            CryptReleaseContext(hProv, 0);
        } else {
            CryptReleaseContext(hProv, 0);
        }
        break;
    }
#endif

    /* Пытаемся использовать /dev/urandom */
    while (1) {
        size_t readed;
        FILE *fos = fopen("/dev/urandom", "rb");
#ifdef WINDOWS
        SetLastError(ERROR_SUCCESS);
#endif

        if (fos == NULL) {
            ERROR_CREATE(RET_FILE_OPEN_ERROR);
            break;
        }

        readed = fread(buf, 1, size, fos);
        for (i = 0; i < readed; i++) {
            rnd8[i] ^= buf[i];
        }

        fclose(fos);
        break;
    }

cleanup:
    free(buf);
    return ret;
}

int rs_std_next_bytes(ByteArray *buf)
{
    size_t i;

    next_bytes_from_os_rng(buf->buf, buf->len);

    srand((unsigned int)time(NULL));
    for (i = 0; i < buf->len; i++) {
        buf->buf[i] ^= rand() % 256;
    }

    return RET_OK;
}

uint64_t rdtsc(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (uint64_t)((uint64_t)ft.dwHighDateTime << 32) | (uint64_t)ft.dwLowDateTime;
#elif defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 * 1000 +  (uint64_t)tv.tv_usec;
#elif defined(SOLARIS)
    return (uint64_t)gethrtime();
#else
    ASSERT(1 == 0);
    return 0;
#endif
}

/*
 * Обновляет массив смещений, по которым выполняются чтения оперативной памяти.
 */
static void update_mem_off(mem_ctx_t *mctx)
{
    int k;

    for (k = 0; k < OFF_BUF_LEN; k++) {
        mctx->off = (mctx->off + 512 * (rand() % (MEM_BUF_SIZE / (4 * 512)))) % (MEM_BUF_SIZE / 4);
        mctx->off_buf[k] = mctx->off;
    }
}

/**
 * Выполняет фиксированное число операций чтения оперативной памяти.
 */
static void mem_noise_func(mem_ctx_t *mctx)
{
    int k;

    for (k = 0; k < OFF_BUF_LEN; k++) {
        mctx->sum += mctx->mem_buf[mctx->off_buf[k]];
    }
}

/**
 * Возвращает время выполнения процессором фиксированного числа
 * операций чтения оперативной памяти в тиках процессора.
 *
 * @return время выполнения фиксированного числа
 *         операций чтения оперативной памяти
 */
static uint64_t get_random_value(mem_ctx_t *mctx)
{
    volatile uint64_t start_tm, end_tm;

    update_mem_off(mctx);

    start_tm = rdtsc();
    mem_noise_func(mctx);
    end_tm = rdtsc();

    return end_tm - start_tm;
}

/**
 * Оставляет в буфере только различные значения.
 * Возвращает количество различных значений.
 */
static void get_distinct(uint64_t *x, int *len)
{
    int i, j, idx;

    idx = 0;
    for (i = 0; i < *len; i++) {
        x[idx] = x[i];
        for (j = 0; j < idx; j++)
            if (x[idx] == x[j]) {
                idx--;
                break;
            }
        idx++;
    }

    *len = idx;
}

/**
 * Возвращает количество граней "честной" кости и номер грани (начиная с 0)
 * соответствующей последовательности независимых случайных величин.
 *
 * Необходимо чтобы n < 2^26.
 *
 * @param x массив содержащий независимые случайные величины
 * @param n число элементов в массиве x
 * @param R порядковый номер S гранной кости (массив из n элементов)
 * @param S количество гранней у кости соответствующей выборке x (массив из n элементов)
 *
 * @return код ошибки
 */
static int unbias_Q1(const uint64_t *x, int n, WordArray **R_out, WordArray **S_out)
{
    /*
     * Количество граней S у "честной" кости не превосходит n!.
     * Так как n < 2^31, то для размещения числа S, а значит и R,
     * достаточно массива типа word_t размера n.
     */
    int i, j;
    int union_n;
    WordArray *R = NULL;
    WordArray *S = NULL;
    WordArray *fac = NULL;
    WordArray *S2 = NULL;
    WordArray *R_add = NULL;

    uint64_t *rank = NULL;
    uint64_t *distinct_x = NULL;
    word_t /**S2, *fac,*/ *fr = NULL;
    int ret = RET_OK;

    CHECK_PARAM(x != NULL);
    CHECK_PARAM(R_out != NULL);
    CHECK_PARAM(S_out != NULL);
    CHECK_PARAM(n > 0);

    /* n < 2^26, так как 3*n*sizeof(word_t) должно умещаться в 32-битный int */
    ASSERT(n < 0x4000000);

    /* Получаем множество различных значений из x */
    MALLOC_CHECKED(distinct_x, n * sizeof(uint64_t));
    memcpy(distinct_x, x, n * sizeof(uint64_t));
    union_n = n;
    get_distinct(distinct_x, &union_n);

    /* Вычисляем rank(x[i],x) */
    MALLOC_CHECKED(rank, n * sizeof(uint64_t));
    for (i = 0; i < n; i++) {
        rank[i] = 0;
        for (j = 0; j < union_n; j++) {
            if (x[i] >= distinct_x[j]) {
                rank[i]++;
            }
        }
    }

    /* Вычисляем fr[i],  1 <= rank <= n.
       Значения хранимые в буфере distinct_x более не нужны. */
    MALLOC_CHECKED(fr, n * sizeof(uint64_t));
    for (i = 0; i < n; i++) {
        fr[i] = 0;
    }
    for (i = 0; i < n; i++) {
        fr[rank[i] - 1]++;
    }

    CHECK_NOT_NULL(S2 = wa_alloc(2 * n));
    factorial(n, S2);

    CHECK_NOT_NULL(fac = wa_alloc(n));

    for (i = 0; i < n; i++) {
        factorial((int)fr[i], fac);
        int_div(S2, fac, S2, NULL);
    }

    /* Вычисляем номер перестановки rank начиная с нулевой.
       Значения хранимые в буфере fac более не нужны, можем использовать R_add. */
    CHECK_NOT_NULL(R = wa_alloc_with_zero(n));
    CHECK_NOT_NULL(S = wa_alloc(n));
    DO(wa_copy_part(S2, 0, n, S));

    CHECK_NOT_NULL(R_add = wa_alloc(n));

    for (i = 0; i < n - 1; i++) {
        int f;
        word_t v, l = 0;
        for (j = 0; j < (int)(rank[i] - 1); j++) {
            l += fr[j];
        }
        v = fr[rank[i] - 1];

        f = (int)(n - i);
        DO(int_mult_and_div(S, l, f, n, R_add));

        int_add(R, R_add, R);
        DO(int_mult_and_div(S, v, f, n, S));

        fr[rank[i] - 1]--;
    }

    DO(wa_copy_part(S2, 0, n, S));

    *R_out = R;
    *S_out = S;
    R = NULL;
    S = NULL;

    ret = RET_OK;

cleanup:

    wa_free(R);
    wa_free(S);
    wa_free(fac);
    wa_free(S2);
    wa_free(R_add);

    free(rank);
    free(distinct_x);
    free(fr);

    return ret;
}

/**
 * Возвращает последовательность бросаний "честной" монеты, соответствующей
 * результату бросания "честной" кости.
 *
 * @param R порядковый номер S гранной кости
 * @param S количество гранней у кости
 * @param n количество элементов в массиве R
 * @param r массив длины n для большого целого числа, битовое представленние
 *           которого, дополненое до rlen бит, соответствует последовательности
 *           бросаний "честной" монеты
 * @param rlen длина битовой последовательности в r
 */
static void unbias_Q2(const WordArray *R, const WordArray *S, WordArray **r, size_t *rlen)
{
    size_t i, k;
    int ret = RET_OK;

    CHECK_NOT_NULL(*r = wa_copy_with_alloc(R));

    k = int_bit_len(S);

    for (i = k - 1; i >= 1; i--) {
        if (int_get_bit(S, i) == 1 && int_get_bit(R, i) == 0) {
            int_truncate(*r, i);
            wa_change_len(*r, WA_LEN_FROM_BITS(i));
            *rlen = i;

            return;
        }
    }

    *rlen = 0;

cleanup:

    return;

}

/**
 * Преобразует выборку случайной величины с произвольным распределением
 * в последовательность равномерно распределенных бит.
 *
 * @param x массив содержащий выборку случайной величины
 * @param size размер элементов массива x в байтах, 0 < x <= 8
 * @param count количество элементов в массиве x, count < 2^25
 * @param r буфер размера size*count для последовательности равномерно распределенных бит
 * @param rlen переменная для размера последовательности r в битах
 *
 * @return код ошибки
 */
int unbias(uint64_t *x, int count, WordArray **r, size_t *rlen)
{
    uint64_t *tx = NULL;
    WordArray *R = NULL;
    WordArray *S = NULL;
    int ret = RET_OK;

    /* n < 2^25, т.к. n*64 должно умещаться в 32-битный int */
    ASSERT(count < 0x2000000);

    MALLOC_CHECKED(tx, sizeof(uint64_t) * count);

    DO(unbias_Q1(x, count, &R, &S));

    unbias_Q2(R, S, r, rlen);

cleanup:
    free(tx);
    wa_free(R);
    wa_free(S);

    return ret;
}

/**
 * Заполняет массив случайными байтами.
 *
 * Генерируются выборки размера n, в них устраняется смещение и
 * результирующие последовательности конкатенируются. Выборки
 * генерируются до тех пор, пока не заполнится буфер rnd.
 *
 * @param rnd буфер, в котором будут размещены случайные байты
 * @param len размер буфера в байтах
 * @param n размер выборки подвергающейся процедуре устранения смещения
 *
 * @return код ошибки
 */
static int rng_next_unbiased_bytes(mem_ctx_t *mctx, void *rnd, size_t len, size_t n)
{
    int ret = RET_OK;
    uint64_t *sample = NULL;
    WordArray *usample = NULL;
    size_t i;
    size_t ulen, off;

    MALLOC_CHECKED(sample, n * sizeof(uint64_t));

    off = 0;
    while (off < 8 * len) {
        for (i = 0; i < n; i++) {
            sample[i] = get_random_value(mctx);
        }

        DO(unbias(sample, (int)n, &usample, &ulen));

        for (i = 0; (i < ulen) && (off + i < 8 * len); i++) {
            SET_BIT((uint8_t *)rnd, off + i, int_get_bit(usample, i));
        }

        wa_free(usample);
        usample = NULL;

        off += ulen;
    }

cleanup:

    free(sample);
    wa_free(usample);

    return ret;
}

int rs_memory_next_bytes(ByteArray *buf)
{
    int ret = RET_OK;

#if !defined(ARM)
    size_t i;
    uint8_t *rnd_buf = NULL;
    mem_ctx_t mctx;

    mctx.mem_buf = NULL;

    CHECK_PARAM(buf != NULL);

    MALLOC_CHECKED(mctx.mem_buf, MEM_BUF_SIZE);
    MALLOC_CHECKED(rnd_buf, buf->len);

    DO(next_bytes_from_os_rng(rnd_buf, buf->len));

    memcpy(buf->buf, rnd_buf, buf->len);

    DO(rng_next_unbiased_bytes(&mctx, rnd_buf, buf->len, INTERNAL_RS_SAMPLE_LEN));

    for (i = 0; i < buf->len; i++) {
        buf->buf[i] ^= rnd_buf[i];
    }

    memset(rnd_buf, 0, buf->len);

    free(mctx.mem_buf);
    free(rnd_buf);

    return ret;

cleanup:
    memset(rnd_buf, 0, buf->len);
    memset(buf->buf, 0, buf->len);

    if (mctx.mem_buf != NULL) {
        free(mctx.mem_buf);
    }
    if (rnd_buf != NULL) {
        free(rnd_buf);
    }

    return ret;
#else
    return CRYPTOS_RET_UNSUPPORTED_METHOD;
#endif

}
