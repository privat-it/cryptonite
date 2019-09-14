#include "kdf.h"
#include "hmac.h"
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
