/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "atest.h"
#include "dstu4145.h"


static void dstu4145_verify_pn(void)
{
    ByteArray *b = ba_alloc_from_be_hex_string("5ff6108462a2dc8210ab403925e638a19c1455d21");
    ByteArray *px_d = ba_alloc_from_be_hex_string("72d867f93a93ac27df9ff01affe74885c8c540420");
    ByteArray *py_d = ba_alloc_from_be_hex_string("0224a9c3947852b97c5599d5f4ab81122adc3fd9b");
    ByteArray *px_pub = ba_alloc_from_be_hex_string("57de7fde023ff929cb6ac785ce4b79cf64abdc2da");
    ByteArray *py_pub = ba_alloc_from_be_hex_string("3e85444324bcf06ad85abf6ad7b5f34770532b9aa");
    ByteArray *n = ba_alloc_from_be_hex_string("400000000000000000002bec12be2262d39bcf14d");
    ByteArray *hash = ba_alloc_from_be_hex_string("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");
    ByteArray *r = ba_alloc_from_le_hex_string("a7088d06937ade9af524a4800d4a01aa0c2cea7402");
    ByteArray *s = ba_alloc_from_le_hex_string("ca5a61b332a3d65b0f238c8e2b83317395860d1002");
    Dstu4145Ctx *ctx = NULL;
    int a = 1;
    int f[5] = {163, 7, 6, 3, 0};

    ASSERT_NOT_NULL(ctx = dstu4145_alloc_pb(f, sizeof(f) / sizeof(f[0]), a, b, n, px_d, py_d));
    ASSERT_RET_OK(dstu4145_init_verify(ctx, px_pub, py_pub));
    ASSERT_RET_OK(dstu4145_verify(ctx, hash, r, s));

cleanup:

    BA_FREE(b, px_d, py_d, px_pub, py_pub, n, hash, r, s);
    dstu4145_free(ctx);
}

void atest_dstu4145(void)
{
    size_t old_err = error_count;

    dstu4145_verify_pn();

    if (old_err == error_count) {
        msg_print_atest("DSTU4145", "[verify-pn]", "OK");
    } else {
        msg_print_atest("DSTU4145", "", "FAILED");
    }
}

