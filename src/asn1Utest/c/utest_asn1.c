/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

int main(void)
{
    utest_any();
    utest_bitstring();
    utest_asn1null();
    utest_bmpstring();
    utest_boolean();
    utest_enumerated();
    utest_generalizedtime();
    utest_graphicstring();
    utest_ia5string();
    utest_integer();
    utest_iso646string();
    utest_nativeenumerated();
    utest_nativeinteger();
    utest_nativereal();
    utest_numericstring();
    utest_object_identifier();
    utest_octetstring();
    utest_printablestring();
    utest_real();
    utest_t61string();
    utest_teletexstring();
    utest_universalstring();
    utest_utctime();
    utest_utf8string();
    utest_visiblestring();

    stacktrace_finalize();

    printf("Total errors: %d\n", (uint32_t) error_count);

    return (error_count > 0) ? -1 : 0;
}

