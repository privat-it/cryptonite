/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PTEST_H
#define CRYPTONITE_PTEST_H

#include "test_utils.h"
#include "ptest_utils.h"

/*Performance tests*/
void ptest_dstu7624_cipher(TableBuilder *table_builder);
void ptest_dstu7564_hash(TableBuilder *table_builder);
void ptest_dstu7564_kmac(TableBuilder *table_builder);
void ptest_gost28147(TableBuilder *table_builder);
void ptest_sha1(TableBuilder *table_builder);
void ptest_sha2(TableBuilder *table_builder);
void ptest_sha2_hmac(TableBuilder *table_builder);
void ptest_aes(TableBuilder *table_builder);
void ptest_des(TableBuilder *table_builder);
void ptest_md5(TableBuilder *table_builder);
void ptest_rsa(TableBuilder *table_builder);
void ptest_gost34_311(TableBuilder *table_builder);
void ptest_gost28147(TableBuilder *table_builder);
void ptest_dstu4145(TableBuilder *table_builder);
void ptest_ecdsa(TableBuilder *table_builder);
void ptest_dsa(TableBuilder *builder);

#endif
