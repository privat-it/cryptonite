/*
 * Приклад: електронний підпис ECDSA (крива SEC P-384 r1).
 */

#include <stdio.h>

#include "byte_array.h"
#include "cryptonite_errors.h"
#include "ecdsa.h"
#include "prng.h"
#include "sha2.h"

#define CHECK(func)                                                     \
    if ((ret = (func)) != RET_OK) {                                     \
        printf("Помилка %d у рядку %d\n", ret, __LINE__);               \
        goto cleanup;                                                   \
    }

int main(void)
{
    int ret = RET_OK;
    ByteArray *data = ba_alloc_from_str("Документ для підпису ECDSA");
    ByteArray *seed = ba_alloc_by_len(40);
    ByteArray *hash = NULL;
    ByteArray *priv = NULL;
    ByteArray *qx = NULL, *qy = NULL;
    ByteArray *r = NULL, *s = NULL;
    PrngCtx *prng = NULL;
    Sha2Ctx *sha = NULL;
    EcdsaCtx *ctx = NULL;

    /* Хеш повідомлення — SHA-384 під пару до P-384. */
    sha = sha2_alloc(SHA2_VARIANT_384);
    CHECK(sha2_update(sha, data));
    CHECK(sha2_final(sha, &hash));

    /* УВАГА: seed константний лише для прикладу! */
    CHECK(ba_set(seed, 0x3c));
    prng = prng_alloc(PRNG_MODE_DEFAULT, seed);

    ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P384_R1);

    CHECK(ecdsa_generate_privkey(ctx, prng, &priv));
    CHECK(ecdsa_get_pubkey(ctx, priv, &qx, &qy));

    CHECK(ecdsa_init_sign(ctx, priv, prng));
    CHECK(ecdsa_sign(ctx, hash, &r, &s));
    printf("Підпис ECDSA створено\n");

    CHECK(ecdsa_init_verify(ctx, qx, qy));
    CHECK(ecdsa_verify(ctx, hash, r, s));
    printf("Підпис коректний\n");

cleanup:
    ecdsa_free(ctx);
    sha2_free(sha);
    prng_free(prng);
    ba_free(data);
    ba_free(seed);
    ba_free(hash);
    ba_free_private(priv);
    ba_free(qx);
    ba_free(qy);
    ba_free(r);
    ba_free(s);
    return (ret == RET_OK) ? 0 : 1;
}
