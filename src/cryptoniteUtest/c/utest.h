/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_UTEST_H
#define CRYPTONITE_UTEST_H

#include "test_utils.h"

void utest_gost28147(void);
void utest_md5(void);
void utest_sha1(void);
void utest_sha2(void);
void utest_ripemd(void);
void utest_dstu7564(void);
void utest_gost34311(void);
void utest_dstu4145(void);
void utest_ecdsa(void);
void utest_rsa(void);
void utest_math_int(void);
void utest_math_gfp(void);
void utest_math_ecp(void);
void utest_math_gf2m(void);
void utest_math_ec2m(void);
void utest_dsa(void);
void utest_des(void);
void utest_aes(void);
void utest_hmac(void);
void utest_dstu7624(void);
void utest_byte_utils(void);
void utest_stacktrace(void);
void utest_byte_array(void);
void utest_rs(void);
void utest_crypto_cache(void);
void utest_gost3410(void);



#endif
