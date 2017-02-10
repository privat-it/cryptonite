/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef SRC_CRYPTONITEPTEST_C_PTEST_UTILS_H_
#define SRC_CRYPTONITEPTEST_C_PTEST_UTILS_H_

void ptest_table_print(TableBuilder *ctx);
void ptest_pthread_generator(void *(*ptest_func)(void *ctx), TableBuilder *table_builder);

#endif /* SRC_CRYPTONITEPTEST_C_PTEST_UTILS_H_ */
