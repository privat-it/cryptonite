# Хешування та MAC

Усі хеш-функції бібліотеки працюють за однією схемою:

```
alloc → [init] → update (скільки завгодно разів) → final → free
```

Дані передаються як `ByteArray *`, результат повертається через вихідний
параметр `ByteArray **`. Функції повертають `int`-код помилки (`RET_OK` — успіх);
див. [Перші кроки](../getting-started.md) щодо обробки помилок.

## ДСТУ 7564:2014 «Купина»

S-box задається при створенні контексту, довжина хешу в байтах (32/48/64) —
при ініціалізації:

```c
#include "dstu7564.h"

ByteArray *data = ba_alloc_from_str("повідомлення");
ByteArray *hash = NULL;
Dstu7564Ctx *ctx = dstu7564_alloc(DSTU7564_SBOX_1);

dstu7564_init(ctx, 64);          /* Купина-512: 64 байти */
dstu7564_update(ctx, data);
dstu7564_final(ctx, &hash);

dstu7564_free(ctx);
ba_free(data);
ba_free(hash);
```

## ГОСТ 34.311-95

Контекст створюється одразу з S-box та синхропосилкою (32 байти), окремого
`init` немає:

```c
#include "gost34_311.h"

ByteArray *sync = ba_alloc_by_len(32);   /* синхропосилка */
ba_set(sync, 0x00);
ByteArray *hash = NULL;
Gost34311Ctx *ctx = gost34_311_alloc(GOST28147_SBOX_ID_1, sync);

gost34_311_update(ctx, data);
gost34_311_final(ctx, &hash);

gost34_311_free(ctx);
ba_free(sync);
ba_free(hash);
```

## SHA-1, SHA-2, MD5

```c
#include "sha1.h"
#include "sha2.h"
#include "md5.h"

Sha1Ctx *sha1 = sha1_alloc();                      /* без параметрів */
Sha2Ctx *sha2 = sha2_alloc(SHA2_VARIANT_256);      /* 224/256/384/512 */
Md5Ctx  *md5  = md5_alloc();

/* далі однаково: xxx_update(ctx, data); xxx_final(ctx, &hash); xxx_free(ctx); */
```

## HMAC

HMAC будується над будь-яким хешем бібліотеки; контекст створюється
конструктором відповідного алгоритму:

```c
#include "hmac.h"

ByteArray *key = ba_alloc_from_str("секретний ключ");
ByteArray *mac = NULL;
HmacCtx *ctx = hmac_alloc_sha2(SHA2_VARIANT_512);
/* також: hmac_alloc_sha1(), hmac_alloc_md5(), hmac_alloc_gost34_311(sbox_id, sync);
   для «Купини» використовуйте власний KMAC — див. нижче */

hmac_init(ctx, key);
hmac_update(ctx, data);
hmac_final(ctx, &mac);

hmac_free(ctx);
ba_free(key);
ba_free(mac);
```

## KMAC на базі «Купини» (ДСТУ 7564)

```c
Dstu7564Ctx *ctx = dstu7564_alloc(DSTU7564_SBOX_1);

dstu7564_init_kmac(ctx, key, 64);    /* ключ + довжина MAC у байтах */
dstu7564_update_kmac(ctx, data);
dstu7564_final_kmac(ctx, &mac);

dstu7564_free(ctx);
```

## CMAC / GMAC на базі «Калини» (ДСТУ 7624)

```c
Dstu7624Ctx *ctx = dstu7624_alloc(DSTU7624_SBOX_1);

dstu7624_init_cmac(ctx, key, block_len, mac_len);   /* або dstu7624_init_gmac(...) */
dstu7624_update_mac(ctx, data);
dstu7624_final_mac(ctx, &mac);

dstu7624_free(ctx);
```

## Імітовставка ГОСТ 28147-89

```c
Gost28147Ctx *ctx = gost28147_alloc(GOST28147_SBOX_ID_1);

gost28147_init_mac(ctx, key);
gost28147_update_mac(ctx, data);
gost28147_final_mac(ctx, &mac);

gost28147_free(ctx);
```

## Поради

- Контекст можна використовувати повторно для нового обчислення, викликавши
  `init` ще раз; для зміни алгоритму/режиму — звільніть і створіть заново.
- `update` можна викликати багато разів — зручно для потокової обробки
  великих файлів частинами.
- Повний робочий приклад: `src/cryptoniteExample/c/cryptonite_example.c`.
