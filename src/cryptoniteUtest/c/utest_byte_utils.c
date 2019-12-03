/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <string.h>

#include "utest.h"
#include "byte_utils_internal.h"


static void test_u8_to_u64(void)
{
    uint8_t from[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    uint64_t exp[] = {0x0807060504030201, 0x100F0E0D0C0B0A09};
    uint64_t to[2];

    ASSERT_RET_OK(uint8_to_uint64(from, 16, to, 2));
    ASSERT_TRUE(!memcmp(exp, to, sizeof(to)));

cleanup:

    return;
}

static void test_u64_to_u8(void)
{
    uint8_t exp[]   = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    uint64_t from[] = {0x0807060504030201, 0x100F0E0D0C0B0A09};
    uint8_t to[16];

    ASSERT_RET_OK(uint64_to_uint8(from, 2, to, sizeof(to)));
    ASSERT_TRUE(!memcmp(exp, to, sizeof(to)));

cleanup:

    return;
}

static void test_u64_to_u8_2(void)
{
    uint8_t exp[]   = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0};
    uint64_t from[] = {0x0807060504030201, 0x100F0E0D0C0B0A09};
    uint8_t to[17];

    ASSERT_RET_OK(uint64_to_uint8(from, 2, to, sizeof(to)));
    ASSERT_TRUE(!memcmp(exp, to, sizeof(to)));

cleanup:

    return;
}

static void test_u32_to_u8(void)
{
    uint8_t exp[]   = {0x01, 0x02, 0x03, 0x04, 0x09, 0x0A, 0x0B, 0x0C};
    uint32_t from[] = {0x04030201, 0x0C0B0A09};
    uint8_t to[8];

    ASSERT_RET_OK(uint32_to_uint8(from, 2, to, 8));
    ASSERT_TRUE(!memcmp(exp, to, sizeof(to)));

cleanup:

    return;
}

static void test_u32_to_u8_2(void)
{
    uint8_t exp[]   = {0x01, 0x02, 0x03, 0x04, 0x09, 0x0A, 0x0B, 0x0C, 0};
    uint32_t from[] = {0x04030201, 0x0C0B0A09};
    uint8_t to[9];

    ASSERT_RET_OK(uint32_to_uint8(from, 2, to, 9));
    ASSERT_TRUE(!memcmp(exp, to, sizeof(to)));

cleanup:

    return;
}

static void test_u64_to_u32(void)
{
    uint64_t from[2] = {0x0807060504030201LLU, 0x100e0d0c0b0a0908LLU};
    uint32_t to[4] = {0};
    uint32_t exp[4] = {0x04030201LU, 0x08070605LU, 0x0b0a0908LU, 0x100e0d0cLU};

    ASSERT_RET_OK(uint64_to_uint32(from, sizeof(from) / sizeof(uint64_t), to, sizeof(to) / sizeof(uint32_t)));
    ASSERT_TRUE(!memcmp(exp, to, sizeof(to)));

cleanup:
    return;
}

static void test_u32_to_u64(void)
{
    uint32_t from[4] = {0x04030201LU, 0x08070605LU, 0x0b0a0908LU, 0x100e0d0cLU};
    uint64_t to[2] = {0};
    uint64_t exp[] = {0x0807060504030201LLU, 0x100e0d0c0b0a0908LLU};

    ASSERT_RET_OK(uint32_to_uint64(from, sizeof(from) / sizeof(uint32_t), to, sizeof(to) / sizeof(uint64_t)));
    ASSERT_TRUE(!memcmp(exp, to, sizeof(to)));

cleanup:
    return;
}

static void test_u8_swap_alloc(void)
{
    uint8_t *test_swap_alloc = NULL;
    uint8_t from[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    uint8_t exp[10] = {0, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    uint8_t test_swap[10];

    ASSERT_NOT_NULL(test_swap_alloc = uint8_swap_with_alloc(from, sizeof(from)));
    ASSERT_TRUE(!memcmp(test_swap_alloc, exp, sizeof(exp)));

    ASSERT_RET_OK(uint8_swap(from, sizeof(from), test_swap, sizeof(from)));
    ASSERT_TRUE(!memcmp(test_swap, exp, sizeof(exp)));

cleanup:

    free(test_swap_alloc);

    return;
}

void utest_byte_utils(void)
{
    test_u8_to_u64();
    test_u32_to_u8();
    test_u32_to_u8_2();
    test_u64_to_u8();
    test_u64_to_u8_2();
    test_u64_to_u32();
    test_u32_to_u64();
    test_u8_swap_alloc();
}
