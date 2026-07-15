# Приклади використання Cryptonite

Кожен файл — самодостатня програма з `main()`, яку можна читати як рецепт.
Докладні пояснення — у [документації](../docs/README.md).

## Криптографічне ядро

| Приклад | Що демонструє |
|---------|---------------|
| [hash_kupyna.c](hash_kupyna.c) | ДСТУ 7564 «Купина»: хеші 256/512, потокова обробка |
| [hash_classic.c](hash_classic.c) | SHA-1, SHA-256, MD5, ГОСТ 34.311 |
| [mac_hmac_kmac.c](mac_hmac_kmac.c) | HMAC-SHA256, KMAC («Купина»), CMAC («Калина») |
| [cipher_kalyna.c](cipher_kalyna.c) | ДСТУ 7624 «Калина»: CTR та AEAD-режим GCM |
| [cipher_gost28147.c](cipher_gost28147.c) | ГОСТ 28147: гамування (CTR), імітовставка |
| [cipher_aes.c](cipher_aes.c) | AES-256-CBC з доповненням PKCS#7 |
| [sign_dstu4145.c](sign_dstu4145.c) | ДСТУ 4145: ключі, підпис, перевірка, виявлення підробки |
| [sign_ecdsa.c](sign_ecdsa.c) | ECDSA на кривій P-384 |
| [sign_rsa.c](sign_rsa.c) | RSA-2048 PKCS#1 v1.5 |

## PKI та сховища

| Приклад | Що демонструє |
|---------|---------------|
| [storage_pkcs12.c](storage_pkcs12.c) | Сховище PKCS#12: створення, генерація ключа, відкриття |
| [cert_selfsigned.c](cert_selfsigned.c) | Випуск самопідписаного сертифіката X.509 (ДСТУ 4145) |
| [cms_signed_data.c](cms_signed_data.c) | CMS SignedData (.p7s): підписання та перевірка |

## Збірка та запуск

Приклади збираються разом з проєктом (див. [docs/building.md](../docs/building.md)):

```sh
cmake -B build
cmake --build build
./build/examples/example_hash_kupyna
```

Кожен приклад повертає 0 при успіху та друкує результат у консоль.

## Важливо

У прикладах seed для ГПВЧ — **константа**, щоб результати були
відтворюваними. У реальному коді ініціалізуйте ГПВЧ справжньою ентропією,
інакше ключі будуть передбачуваними.

Розгорнуті сценарії (OCSP, TSP, CRL, EnvelopedData, CAdES) — у
`src/pkiExample/c/pki_example.c`.
