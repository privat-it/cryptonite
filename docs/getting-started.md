# Перші кроки

## Підключення

Зберіть бібліотеки (див. [Збірка](building.md)) і підключіть заголовки з
`src/cryptonite/c` (криптоядро), за потреби — `src/pkix/c/*` та
`src/storage/c`. Лінкуйте у порядку залежностей:
`storage → pkix → asn1 → cryptonite → pthread_impl`.

Якщо компілюєте без CMake-проєкту — визначте макрос
`CRYPTONITE_EXPORT=extern`.

## ByteArray — центральний тип даних

Усі дані (ключі, повідомлення, хеші, підписи) передаються через непрозорий
тип `ByteArray` з `byte_array.h`:

```c
/* створення */
ByteArray *a = ba_alloc_from_str("текст");                /* з рядка */
ByteArray *b = ba_alloc_from_uint8(buf, buf_len);         /* з масиву байтів */
ByteArray *c = ba_alloc_by_len(32);                       /* порожній, 32 байти */
ByteArray *d = ba_alloc_from_le_hex_string("00afb1");     /* з hex-рядка */
ba_alloc_from_file("шлях/до/файла", &e);                  /* з файла */

/* доступ до даних */
const uint8_t *raw = ba_get_buf(a);
size_t len = ba_get_len(a);
ba_to_file(a, "вихідний.bin");

/* операції */
ba_cmp(a, b);        /* 0 == однакові */
ba_set(c, 0x00);     /* заповнити значенням */
ba_xor(a, b);        /* a ^= b */

/* звільнення */
ba_free(a);
ba_free_private(key);   /* для секретів: обнуляє пам'ять перед звільненням */
```

`ba_free(NULL)` безпечний — це спрощує код очищення.

## Обробка помилок

Майже всі функції повертають `int`: `RET_OK` (0) — успіх, інакше — код
помилки. Функції-конструктори (`*_alloc`) повертають вказівник, який треба
перевіряти на `NULL`. Коди криптоядра — у `cryptonite_errors.h`
(наприклад, `RET_INVALID_PARAM`, `RET_VERIFY_FAILED`, `RET_INVALID_KEY_SIZE`);
у шарів pkix і storage — власні файли кодів (`pkix_errors.h`,
`storage_errors.h`).

Усталений патерн у кодовій базі — `goto cleanup` з безумовним звільненням:

```c
int compute_hash(const ByteArray *data, ByteArray **hash)
{
    int ret = RET_OK;
    Dstu7564Ctx *ctx = NULL;

    ctx = dstu7564_alloc(DSTU7564_SBOX_1);
    if (ctx == NULL) { ret = RET_MEMORY_ALLOC_ERROR; goto cleanup; }

    if ((ret = dstu7564_init(ctx, 32)) != RET_OK) goto cleanup;
    if ((ret = dstu7564_update(ctx, data)) != RET_OK) goto cleanup;
    if ((ret = dstu7564_final(ctx, hash)) != RET_OK) goto cleanup;

cleanup:
    dstu7564_free(ctx);   /* free(NULL) безпечний для всіх контекстів */
    return ret;
}
```

## Життєвий цикл контекстів

Кожен алгоритм працює через непрозорий контекст за схемою:

```
XxxCtx *ctx = xxx_alloc(параметри алгоритму);
xxx_init_режим(ctx, ключ/параметри);      /* можна повторно для нового обчислення */
xxx_update / xxx_encrypt / xxx_sign ...;
xxx_free(ctx);
```

Вихідні параметри виду `ByteArray **out` створюються функцією — звільняє їх
викликач через `ba_free`.

## Генератор псевдовипадкових чисел

Операції з ключами вимагають контекст ГПВЧ (`prng.h`). **Seed має бути
справжньою ентропією** (у прикладах бібліотеки для простоти використовуються
константи — у реальному коді так робити не можна):

```c
ByteArray *seed = ba_alloc_by_len(40);
/* заповніть seed системною ентропією! */
PrngCtx *prng = prng_alloc(PRNG_MODE_DEFAULT, seed);   /* PRNG_MODE_DSTU — для ДСТУ 4145 */

ByteArray *key = NULL;
aes_generate_key(prng, 32, &key);

prng_free(prng);
ba_free(seed);
ba_free_private(key);
```

## Мінімальна програма

```c
#include <stdio.h>
#include "byte_array.h"
#include "dstu7564.h"
#include "cryptonite_errors.h"

int main(void)
{
    ByteArray *data = ba_alloc_from_str("Привіт, Cryptonite!");
    ByteArray *hash = NULL;
    Dstu7564Ctx *ctx = dstu7564_alloc(DSTU7564_SBOX_1);

    if (ctx == NULL || dstu7564_init(ctx, 32) != RET_OK
            || dstu7564_update(ctx, data) != RET_OK
            || dstu7564_final(ctx, &hash) != RET_OK) {
        printf("Помилка обчислення хешу\n");
    } else {
        ba_print(stdout, hash);
    }

    dstu7564_free(ctx);
    ba_free(data);
    ba_free(hash);
    return 0;
}
```

## Куди далі

- [Хешування та MAC](guides/hashing.md)
- [Симетричне шифрування](guides/encryption.md)
- [Електронний підпис](guides/signatures.md)
- [Сертифікати та PKI](guides/pki.md)
- [Ключові сховища](guides/storage.md)
