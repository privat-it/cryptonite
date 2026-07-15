# Електронний підпис

Загальний патерн для всіх алгоритмів:

```
alloc(параметри) → generate_privkey → get_pubkey
   → init_sign(priv, prng) → sign(hash)     — підписання
   → init_verify(pub)      → verify(hash)   — перевірка
→ free
```

Підписується **хеш** повідомлення (обчисліть його заздалегідь — див.
[Хешування](hashing.md)). Для ЕЦП на еліптичних кривих підпис — це пара
`(r, s)`; `verify` повертає `RET_OK`, якщо підпис коректний
(`RET_VERIFY_FAILED` — якщо ні).

## ДСТУ 4145-2002

Національний стандарт ЕЦП на еліптичних кривих у полях GF(2^m).
15 стандартних наборів параметрів: 10 у поліноміальному базисі
(`DSTU4145_PARAMS_ID_M163_PB` … `M431_PB`) та 5 в оптимальному нормальному
(`M173_ONB` … `M431_ONB`). ГПВЧ — обов'язково в режимі `PRNG_MODE_DSTU`.

```c
#include "dstu4145.h"

PrngCtx *prng = prng_alloc(PRNG_MODE_DSTU, seed);
Dstu4145Ctx *ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);
ByteArray *priv = NULL, *qx = NULL, *qy = NULL, *r = NULL, *s = NULL;

/* ключова пара */
dstu4145_generate_privkey(ctx, prng, &priv);
dstu4145_get_pubkey(ctx, priv, &qx, &qy);

/* підписання */
dstu4145_init_sign(ctx, priv, prng);
dstu4145_sign(ctx, hash, &r, &s);

/* перевірка */
dstu4145_init_verify(ctx, qx, qy);
int ret = dstu4145_verify(ctx, hash, r, s);   /* RET_OK == підпис коректний */

dstu4145_free(ctx);
prng_free(prng);
ba_free_private(priv);
ba_free(qx); ba_free(qy); ba_free(r); ba_free(s);
```

Додатково: стиснення публічного ключа
(`dstu4145_compress_pubkey`/`dstu4145_decompress_pubkey`), протокол
Діффі-Хеллмана (`dstu4145_dh`), власні параметри кривої
(`dstu4145_alloc_pb`/`dstu4145_alloc_onb`), прискорення передобчисленнями
(`dstu4145_set_opt_level`, див. `opt_level.h` та `crypto_cache.h`).

## ECDSA

Той самий потік, що й ДСТУ 4145; параметри — стандартні криві NIST/SEC
(наприклад, `ECDSA_PARAMS_ID_SEC_P384_R1`), ГПВЧ — `PRNG_MODE_DEFAULT`:

```c
#include "ecdsa.h"

EcdsaCtx *ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P384_R1);

ecdsa_generate_privkey(ctx, prng, &priv);
ecdsa_get_pubkey(ctx, priv, &qx, &qy);
ecdsa_init_sign(ctx, priv, prng);
ecdsa_sign(ctx, hash, &r, &s);
ecdsa_init_verify(ctx, qx, qy);
ecdsa_verify(ctx, hash, r, s);

ecdsa_free(ctx);
```

## DSA

Публічний ключ — один `ByteArray` (не пара). Розміри p і q задаються
при створенні контексту:

```c
#include "dsa.h"

DsaCtx *ctx = dsa_alloc_ext(1024, 160, prng);
ByteArray *priv = NULL, *pub = NULL;

dsa_generate_privkey(ctx, prng, &priv);
dsa_get_pubkey(ctx, priv, &pub);
dsa_init_sign(ctx, priv, prng);
dsa_sign(ctx, hash, &r, &s);
dsa_init_verify(ctx, pub);
dsa_verify(ctx, hash, r, s);

dsa_free(ctx);
```

## RSA (PKCS#1 v1.5)

Підпис — один `ByteArray`. Хеш-алгоритм задається константою
(наприклад, `RSA_HASH_SHA1`) — функція сама обгортає хеш у структуру
DigestInfo:

```c
#include "rsa.h"

RsaCtx *ctx = rsa_alloc();
ByteArray *n = NULL, *priv = NULL, *sign = NULL;
uint8_t e_bytes = 3;
ByteArray *e = ba_alloc_from_uint8(&e_bytes, 1);   /* публічна експонента */

rsa_generate_privkey(ctx, prng, 1024, e, &n, &priv);   /* 1024 — біти модуля */

rsa_init_sign_pkcs1_v1_5(ctx, RSA_HASH_SHA1, n, priv);
rsa_sign_pkcs1_v1_5(ctx, hash, &sign);

rsa_init_verify_pkcs1_v1_5(ctx, RSA_HASH_SHA1, n, e);
rsa_verify_pkcs1_v1_5(ctx, hash, sign);

rsa_free(ctx);
```

## Практичні зауваження

- **Seed для ГПВЧ** у продуктивному коді має бути справжньою ентропією;
  для ДСТУ 4145 використовуйте виключно `PRNG_MODE_DSTU`.
- Приватні ключі звільняйте через `ba_free_private()`.
- Для ДСТУ 4145 операції на кривій можна суттєво прискорити:
  `crypto_cache_add_any_new(OPT_LEVEL_COMB_5_WIN_5)` перед створенням
  контекстів (див. `crypto_cache.h`).
- RSA-1024, DSA-1024 та SHA-1 наведені як приклади API — для нового коду
  обирайте RSA ≥ 3072 і SHA-256+.
- Підпис сертифікатів та CMS-контейнерів робиться не напряму, а через
  адаптери шару pkix — див. [Сертифікати та PKI](pki.md).
