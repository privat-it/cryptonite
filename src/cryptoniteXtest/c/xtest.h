/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef XTEST_H
#define XTEST_H

#include "xtest_utils.h"


#ifdef __cplusplus
extern "C" {  
#endif

void xtest_aes(XtestSt *xtest_ctx, TableBuilder *ctx);
void xtest_ripemd(XtestSt *xtest_ctx, TableBuilder *ctx);
void xtest_sha(XtestSt *xtest_ctx, TableBuilder *ctx);
void xtest_des(XtestSt *xtest_ctx, TableBuilder *ctx);
void xtest_md5(XtestSt *xtest_ctx, TableBuilder *ctx);
void xtest_rsa(TableBuilder *ctx);
void xtest_gost28147(XtestSt *xtest_ctx, TableBuilder *ctx);
void xtest_gost34_311(XtestSt *xtest_ctx, TableBuilder *ctx);

void xtest_dstu7564(XtestSt *xtest_ctx, TableBuilder *ctx);
void xtest_dstu7624(XtestSt *xtest_ctx, TableBuilder *ctx);
void xtest_dstu4145(TableBuilder *ctx);
void xtest_ecdsa(TableBuilder *ctx);

#ifdef __cplusplus  
} // extern "C"  
#endif

#endif /* XTEST_H */

