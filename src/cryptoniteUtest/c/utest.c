/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

int main(void)
{
    utest_stacktrace();
    utest_byte_utils();
    utest_byte_array();
    utest_rs();

    utest_math_int();
    utest_math_gfp();
    utest_math_ecp();
    utest_math_gf2m();
    utest_math_ec2m();

    utest_md5();
    utest_ripemd();
    utest_sha1();
    utest_gost28147();
    utest_sha2();
    utest_dstu7564();

    utest_des();
    utest_aes();
    utest_gost34311();
    utest_dstu7624();

    utest_hmac();

    utest_dstu4145();
    utest_ecdsa();
    utest_rsa();
    utest_dsa();
    utest_gost3410();

    utest_crypto_cache();

    stacktrace_finalize();

    printf("Total errors: %d\n", (uint32_t) error_count);

    return (error_count > 0) ? -1 : 0;
}
