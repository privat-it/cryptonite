# Документація Cryptonite

## Для початку

- [Архітектура бібліотеки](architecture.md) — шари, модулі, наскрізні угоди
- [Збірка](building.md) — CMake, опції, тести (CTest), встановлення
- [Перші кроки](getting-started.md) — ByteArray, обробка помилок, перша програма

## Практичні гайди

- [Хешування та MAC](guides/hashing.md) — «Купина» (ДСТУ 7564), ГОСТ 34.311, SHA-2, HMAC
- [Симетричне шифрування](guides/encryption.md) — «Калина» (ДСТУ 7624), ГОСТ 28147, AES
- [Електронний підпис](guides/signatures.md) — ДСТУ 4145, ECDSA, RSA
- [Сертифікати та PKI](guides/pki.md) — X.509, CMS-підписи, OCSP/TSP
- [Ключові сховища](guides/storage.md) — PKCS#8, PKCS#12

## Довідник API

Довідкова документація генерується Doxygen з коментарів у заголовках:

```
doxygen Doxyfile
```

Результат — `docs/api/html/index.html`. Потрібен [Doxygen](https://www.doxygen.nl/) ≥ 1.9.

## Приклади

Дванадцять коротких самодостатніх прикладів — в [`examples/`](../examples/README.md)
(хеші, MAC, шифри, підписи, PKCS#12, сертифікати, CMS).

Розгорнуті демонстраційні програми — у складі проєкту:

- `src/cryptoniteExample/c/cryptonite_example.c` — криптографічні примітиви
- `src/pkiExample/c/pki_example.c` — сертифікати, CMS, OCSP/TSP, сховища
