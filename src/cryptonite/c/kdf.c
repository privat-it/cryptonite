#include "kdf.h"
#include "hmac.h"
#include "gost34_311.h"
#include "sha1.h"
#include "md5.h"
#include "macros_internal.h"

int kdf_pbkdf2(const char *pass, const ByteArray *salt, unsigned long iterations,
        size_t key_len, Pbkdf2HmacId id, ByteArray **dk)
{
    int ret = RET_OK;
    HmacCtx *ctx = NULL;
    ByteArray *iv = NULL;
    ByteArray *pass_ba = NULL;
    ByteArray *count_ba = NULL;
    ByteArray *key = NULL;
    ByteArray *out = NULL;
    ByteArray *u = NULL;
    size_t cplen = 0;
    size_t i;
    unsigned int count = 1;
    unsigned char count_buf[4];
    unsigned int hash_len = 0;

    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(salt != NULL);
    CHECK_PARAM(dk != NULL);

    CHECK_NOT_NULL(out = ba_alloc());

    CHECK_NOT_NULL(pass_ba = ba_alloc_from_str(pass));

    /* F(P, S, c, i) = U1 xor U2 xor ... Uc
     *
     * U1 = PRF(P, S || i)
     * U2 = PRF(P, U1)
     * Uc = PRF(P, Uc-1)
     *
     * T_1 = F (P, S, c, 1) ,
     * T_2 = F (P, S, c, 2) ,
     * ...
     * T_l = F (P, S, c, l)
     */

    switch (id) {
    case PBKDF2_GOST_HMAC_ID:
        CHECK_NOT_NULL(iv = ba_alloc_by_len(32));
        DO(ba_set(iv, 0));
        CHECK_NOT_NULL((ctx = hmac_alloc_gost34_311(GOST28147_SBOX_ID_1, iv)));
        hash_len = 32;
        ba_free(iv);
        iv = NULL;
        break;
    case PBKDF2_SHA1_HMAC_ID:
        CHECK_NOT_NULL(ctx = hmac_alloc_sha1());
        hash_len = 20;
        break;
    case PBKDF2_SHA224_HMAC_ID:
        CHECK_NOT_NULL(ctx = hmac_alloc_sha2(SHA2_VARIANT_224));
        hash_len = 28;
        break;
    case PBKDF2_SHA256_HMAC_ID:
        CHECK_NOT_NULL(ctx = hmac_alloc_sha2(SHA2_VARIANT_256));
        hash_len = 32;
        break;
    case PBKDF2_SHA384_HMAC_ID:
        CHECK_NOT_NULL(ctx = hmac_alloc_sha2(SHA2_VARIANT_384));
        hash_len = 48;
        break;
    case PBKDF2_SHA512_HMAC_ID:
        CHECK_NOT_NULL(ctx = hmac_alloc_sha2(SHA2_VARIANT_512));
        hash_len = 64;
        break;
    default:
        SET_ERROR(RET_UNSUPPORTED_PBKDF2_HMAC_ID);
    }

    while (key_len) {

        if (key_len > hash_len) {
            cplen = hash_len;
        } else {
            cplen = key_len;
        }

        count_buf[0] = (count >> 24) & 0xff;
        count_buf[1] = (count >> 16) & 0xff;
        count_buf[2] = (count >> 8) & 0xff;
        count_buf[3] = count & 0xff;

        CHECK_NOT_NULL((count_ba = ba_alloc_from_uint8(count_buf, sizeof(count_buf))));

        if (count == 1) {
            DO(hmac_init(ctx, pass_ba));
        }
        DO(hmac_update(ctx, salt));
        DO(hmac_update(ctx, count_ba));
        DO(hmac_final(ctx, &u));

        CHECK_NOT_NULL(key = ba_copy_with_alloc(u, 0, cplen));

        for (i = 1; i < iterations; i++) {
            DO(hmac_update(ctx, u));

            ba_free(u);
            u = NULL;

            DO(hmac_final(ctx, &u)); //Hmac reset выполняется при функции final.
            DO(ba_xor(key, u));
        }

        //Добавляем результат в Т
        ba_append(key, 0, cplen, out);
        //Увеличиваем счетчик.
        count++;
        key_len -= cplen;

        ba_free(count_ba);
        ba_free(key);
        ba_free(u);
        count_ba = NULL;
        key = NULL;
        u = NULL;

    }
    *dk = out;
    out = NULL;

cleanup:

    ba_free(out);
    ba_free(key);
    ba_free(u);
    ba_free(iv);
    ba_free(count_ba);
    ba_free(pass_ba);

    hmac_free(ctx);

    return ret;
}

int kdf_pbkdf1(const char *pass, const ByteArray *salt, unsigned long iterations,
        size_t key_len, Pbkdf1HashId id, ByteArray **dk)
{
    int ret = RET_OK;
    ByteArray *pass_ba = NULL;
    ByteArray *sync = NULL;
    ByteArray *buf = NULL;
    unsigned int hash_len = 0;
    Gost34311Ctx *gctx = NULL;
    Sha1Ctx *sctx = NULL;
    Md5Ctx *mctx = NULL;

    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(dk != NULL);

    CHECK_NOT_NULL(pass_ba = ba_alloc_from_str(pass));

    if (salt != NULL) {
        ba_append(salt, 0, ba_get_len(salt), pass_ba);
    }

    switch (id) {
    case PBKDF1_GOST_HASH_ID:
        CHECK_NOT_NULL(sync = ba_alloc_by_len(32));
        DO(ba_set(sync, 0));

        CHECK_NOT_NULL(gctx = gost34_311_alloc(GOST28147_SBOX_ID_1, sync));

        gost34_311_update(gctx, pass_ba);
        gost34_311_final(gctx, &buf);

        for (unsigned long i = 1; i < iterations; ++i) {
            gost34_311_update(gctx, buf);
            ba_free(buf);
            gost34_311_final(gctx, &buf);
        }
        hash_len = 32;
        ba_free(sync);
        sync = NULL;
        break;
    case PBKDF1_SHA1_HASH_ID:
        CHECK_NOT_NULL(sctx = sha1_alloc());

        sha1_update(sctx, pass_ba);
        sha1_final(sctx, &buf);

        for (unsigned long i = 1; i < iterations; ++i) {
            sha1_update(sctx, buf);
            ba_free(buf);
            sha1_final(sctx, &buf);
        }
        hash_len = 20;
        break;
    case PBKDF1_MD5_HASH_ID:
        CHECK_NOT_NULL(mctx = md5_alloc());
        md5_update(mctx, pass_ba);
        md5_final(mctx, &buf);

        for (unsigned long i = 1; i < iterations; ++i) {
            md5_update(mctx, buf);
            ba_free(buf);
            md5_final(mctx, &buf);
        }
        hash_len = 16;
        break;
    default:
        SET_ERROR(RET_UNSUPPORTED_PBKDF2_HMAC_ID);
    }

    if (key_len >= hash_len) {
        key_len = hash_len;
    } else {
        DO(ba_change_len(buf, key_len));
    }
    *dk = buf;

    buf = NULL;

cleanup:
    ba_free(buf);
    ba_free(sync);
    ba_free(pass_ba);
    gost34_311_free(gctx);
    md5_free(mctx);
    sha1_free(sctx);
    return ret;
}
