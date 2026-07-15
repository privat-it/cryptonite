# Cryptonite

[![CI](https://github.com/Hacksli/cryptonite/actions/workflows/ci.yml/badge.svg)](https://github.com/Hacksli/cryptonite/actions/workflows/ci.yml)
[![License: BSD](https://img.shields.io/badge/License-BSD-blue.svg)](LICENSE)

Cryptonite — криптографічна бібліотека мовою C з підтримкою українських
стандартів криптографічного захисту інформації та криптоконтейнерів.

*Cryptonite is a C crypto library with support of Ukrainian cryptographic
standards and cryptocontainers.*

Бібліотека пройшла державну експертизу у сфері КЗІ — експертний висновок
[№ 04/03/02-4834 від 30.11.2016](http://www.dsszzi.gov.ua/dsszzi/control/uk/publish/article?art_id=283948&cat_id=72110)
«Програмний виріб криптографічного захисту інформації "CRYPTONITE"
UA.14360570.00001-01 90 01-1».

## Можливості

| Категорія | Алгоритми |
|-----------|-----------|
| Хеш-функції | **ДСТУ 7564:2014 «Купина»**, ГОСТ 34.311-95, SHA-1, SHA-2, MD5, RIPEMD |
| Блокові шифри | **ДСТУ 7624:2014 «Калина»** (11 режимів, зокрема AEAD GCM/CCM), ДСТУ ГОСТ 28147:2009 «Магма», AES, DES/3DES |
| Електронний підпис | **ДСТУ 4145-2002** (15 стандартних кривих), ГОСТ 34.310-95, ECDSA, DSA, RSA |
| MAC | HMAC, KMAC («Купина»), CMAC/GMAC («Калина»), імітовставка ГОСТ 28147 |
| PKI | Сертифікати X.509, CSR, CRL, OCSP, TSP, CMS (SignedData/EnvelopedData), CAdES |
| Сховища | PKCS#5, PKCS#8, PKCS#12 |

Без зовнішніх залежностей. Платформи: Windows, Linux, macOS, Android, iOS.

## Швидкий старт

```sh
cmake -B build
cmake --build build
./build/examples/example_hash_kupyna
```

Хеш «Купина» за ДСТУ 7564:

```c
#include "byte_array.h"
#include "dstu7564.h"

ByteArray *data = ba_alloc_from_str("повідомлення");
ByteArray *hash = NULL;
Dstu7564Ctx *ctx = dstu7564_alloc(DSTU7564_SBOX_1);

dstu7564_init(ctx, 32);          /* Купина-256 */
dstu7564_update(ctx, data);
dstu7564_final(ctx, &hash);

dstu7564_free(ctx);
ba_free(data);
ba_free(hash);
```

## Документація

- **[Документація](docs/README.md)** — архітектура, збірка, перші кроки
- **Гайди**: [хешування](docs/guides/hashing.md) ·
  [шифрування](docs/guides/encryption.md) ·
  [підписи](docs/guides/signatures.md) ·
  [PKI](docs/guides/pki.md) ·
  [сховища](docs/guides/storage.md)
- **[Приклади](examples/README.md)** — 12 самодостатніх програм
- **Довідник API** — генерується Doxygen: `doxygen Doxyfile` →
  `docs/api/html/index.html`

## Збірка

Основна система збірки — **CMake** ≥ 3.16 (докладно — у
[docs/building.md](docs/building.md)): бібліотеки `cryptonite`, `asn1`,
`pkix`, `storage` (static, опційно shared через `BUILD_SHARED_LIBS`),
установлення через `cmake --install`, тести через `ctest`.

Історична Gradle-збірка (зокрема Android-скрипти) застаріла й не
підтримується сучасними версіями Gradle.

## Ліцензія

BSD. Див. [LICENSE](LICENSE).
Copyright (c) 2016 PrivatBank IT.
