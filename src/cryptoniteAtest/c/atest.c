/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "atest.h"

int main(void)
{
    PR("+------------------------------------------------------------------------------+\n");
    PR("|                               ACCEPT TESTS                                   |\n");
    PR("+------------------------------------------------------------------------------+\n");

    atest_padding();
    atest_dstu7624();
    atest_dstu7564();
    atest_gost28147();
    atest_gost34_311();
    atest_sha1();
    atest_sha2();
    atest_aes();
    atest_des();
    atest_md5();
    atest_ripemd();
    atest_dsa();
    atest_ecdsa();
    atest_dstu4145();

    stacktrace_finalize();

    return (error_count > 0) ? -1 : 0;
}

