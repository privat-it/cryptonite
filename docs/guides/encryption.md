# Симетричне шифрування

Загальний патерн для всіх шифрів:

```
alloc(sbox) → generate_key → init_<режим>(ключ[, IV]) → encrypt / decrypt → free
```

Ключі генеруються через контекст ГПВЧ (див. [Перші кроки](../getting-started.md)):

```c
ByteArray *key = NULL;
dstu7624_generate_key(prng, 64, &key);   /* aes_generate_key, des_generate_key — аналогічно */
```

Для повторної операції (наприклад, розшифрування після шифрування)
контекст ініціалізують тим самим `init_*` ще раз.

## ДСТУ 7624:2014 «Калина»

Ключ 16/32/64 байти, розмір блока 16/32/64 байти. Найширший набір режимів —
11: ECB, CBC, CFB, OFB, CTR, XTS, KW (обгортання ключів), AEAD-режими
CCM і GCM, MAC-режими CMAC і GMAC.

```c
#include "dstu7624.h"

Dstu7624Ctx *ctx = dstu7624_alloc(DSTU7624_SBOX_1);

/* режими без IV — розмір блока передається в init: */
dstu7624_init_ecb(ctx, key, 64);
dstu7624_init_kw(ctx, key, 64);

/* режими з IV (розмір IV = розмір блока): */
dstu7624_init_cbc(ctx, key, iv);
dstu7624_init_ctr(ctx, key, iv);
dstu7624_init_ofb(ctx, key, iv);
dstu7624_init_xts(ctx, key, iv);
dstu7624_init_cfb(ctx, key, iv, q);     /* q — параметр зворотного зв'язку */

dstu7624_encrypt(ctx, data, &encrypted);
dstu7624_init_cbc(ctx, key, iv);        /* повторний init перед decrypt */
dstu7624_decrypt(ctx, encrypted, &decrypted);

dstu7624_free(ctx);
```

### Автентифіковане шифрування (CCM / GCM)

Крім шифротексту повертається імітовставка (MAC); додатково автентифікуються
дані `auth_data`, які не шифруються:

```c
ByteArray *mac = NULL, *encrypted = NULL, *decrypted = NULL;

dstu7624_init_ccm(ctx, key, iv, q, 64 /* n_max */);
/* або: dstu7624_init_gcm(ctx, key, iv, q); */

dstu7624_encrypt_mac(ctx, auth_data, data, &mac, &encrypted);

dstu7624_init_ccm(ctx, key, iv, q, 64);
dstu7624_decrypt_mac(ctx, auth_data, encrypted, mac, &decrypted);
/* повертає помилку, якщо MAC не збігається — дані підроблено */
```

## ДСТУ ГОСТ 28147:2009 («Магма»)

Ключ 32 байти, блок 8 байтів, IV 8 байтів. Режими: ECB, CTR (гамування),
CFB (гамування зі зворотним зв'язком), MAC (імітовставка).
18 стандартних таблиць замін (`GOST28147_SBOX_ID_1` … `GOST28147_SBOX_ID_18`,
серед них ДКЕ №1, CryptoPro з RFC 4357) або власна через
`gost28147_alloc_user_sbox()`.

```c
#include "gost28147.h"

Gost28147Ctx *ctx = gost28147_alloc(GOST28147_SBOX_ID_1);

gost28147_init_ctr(ctx, key, iv);   /* або init_ecb(ctx, key) / init_cfb(ctx, key, iv) */
gost28147_encrypt(ctx, data, &encrypted);

gost28147_init_ctr(ctx, key, iv);
gost28147_decrypt(ctx, encrypted, &decrypted);

gost28147_free(ctx);
```

## AES

Ключ 16/24/32 байти, блок та IV — 16 байтів. Режими: ECB, CBC, CFB, OFB, CTR.

```c
#include "aes.h"

AesCtx *ctx = aes_alloc();

aes_init_cbc(ctx, key, iv);    /* aes_init_ecb(ctx, key) — без IV */
aes_encrypt(ctx, data, &encrypted);

aes_init_cbc(ctx, key, iv);
aes_decrypt(ctx, encrypted, &decrypted);

aes_free(ctx);
```

У режимі CBC розмір даних має бути кратним 16 байтам (окрім останнього
блока при шифруванні) — за потреби застосуйте доповнення з `paddings.h`
(`make_pkcs7_padding`/`make_pkcs7_unpadding`, `make_iso_7816_4_padding`).

## DES / 3DES

Ключ 3DES — 24 байти, блок та IV — 8 байтів. Режими: ECB, CBC, CFB, OFB, CTR.
Зверніть увагу: функції шифрування для 3DES — `des3_encrypt`/`des3_decrypt`
при спільному контексті `DesCtx`:

```c
#include "des.h"

DesCtx *ctx = des_alloc();

des_init_cbc(ctx, key, iv);
des3_encrypt(ctx, data, &encrypted);

des_init_cbc(ctx, key, iv);
des3_decrypt(ctx, encrypted, &decrypted);

des_free(ctx);
```

## Застереження

- **DES, ECB-режим і короткі ключі — застарілі**; для нового коду
  використовуйте «Калину» або AES в AEAD/CTR/CBC-режимах.
- IV для CTR/CFB/OFB/GCM **не повинен повторюватися** з тим самим ключем.
- Секретні ключі звільняйте через `ba_free_private()` — вона обнуляє пам'ять.
- Повний робочий приклад усіх режимів: `src/cryptoniteExample/c/cryptonite_example.c`.
