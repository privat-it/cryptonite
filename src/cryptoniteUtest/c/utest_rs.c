/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "rs.h"

static void test_std_next_bytes(void)
{
    ByteArray *test_rand1 = NULL;
    ByteArray *test_rand2 = NULL;

    ASSERT_NOT_NULL(test_rand1 = ba_alloc_by_len(40));
    ASSERT_NOT_NULL(test_rand2 = ba_alloc_by_len(40));

    ASSERT_RET_OK(rs_std_next_bytes(test_rand1));
    ASSERT_RET_OK(rs_std_next_bytes(test_rand2));
    //Числа должны получиться разные
    ASSERT_TRUE(ba_cmp(test_rand1, test_rand2));

cleanup:
    BA_FREE(test_rand1, test_rand2);
}

static void test_memory_next_bytes(void)
{
    ByteArray *test_rand1 = NULL;
    ByteArray *test_rand2 = NULL;

    ASSERT_NOT_NULL(test_rand1 = ba_alloc_by_len(40));
    ASSERT_NOT_NULL(test_rand2 = ba_alloc_by_len(40));

    ASSERT_RET_OK(ba_set(test_rand1, 0x00));
    ASSERT_RET_OK(ba_set(test_rand2, 0x00));

    ASSERT_RET_OK(rs_memory_next_bytes(test_rand1));
    ASSERT_RET_OK(rs_memory_next_bytes(test_rand2));
    //Числа должны получиться разные
    ASSERT_TRUE(ba_cmp(test_rand1, test_rand2) != 0);

cleanup:
    BA_FREE(test_rand1, test_rand2);
}

void utest_rs(void)
{
    test_std_next_bytes();
    test_memory_next_bytes();
}
