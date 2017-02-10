/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "test_utils.h"

int main(void)
{
    utest_pkcs12_dstu();
    utest_pkcs12_ecdsa();
    utest_pkcs5();

    printf("Total errors: %d\n", (int)error_count);

    stacktrace_finalize();
    fflush(stdout);

    return (error_count > 0) ? -1 : 0;
}
