/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_UTEST_ASN1_H
#define CRYPTONITE_UTEST_ASN1_H

#include "test_utils.h"
#include "asn1_utils.h"

#define ASSERT_ASN_ALLOC(obj) {int ret = RET_OK; ASN_ALLOC(obj); if (ret != RET_OK) { goto cleanup;} }

void utest_any(void);
void utest_bitstring(void);
void utest_asn1null(void);
void utest_bmpstring(void);
void utest_boolean(void);
void utest_enumerated(void);
void utest_generalizedtime(void);
void utest_graphicstring(void);
void utest_ia5string(void);
void utest_integer(void);
void utest_iso646string(void);
void utest_nativeenumerated(void);
void utest_nativeinteger(void);
void utest_nativereal(void);
void utest_numericstring(void);
void utest_object_identifier(void);
void utest_octetstring(void);
void utest_printablestring(void);
void utest_real(void);
void utest_t61string(void);
void utest_teletexstring(void);
void utest_universalstring(void);
void utest_utctime(void);
void utest_utf8string(void);
void utest_visiblestring(void);

#endif //CRYPTONITE_UTEST_ASN1_H
