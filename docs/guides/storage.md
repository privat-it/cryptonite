# Ключові сховища

Шар `storage` реалізує файлові контейнери ключів: PKCS#12 (основний формат
сховища), PKCS#8 (контейнер приватного ключа), PKCS#5 (шифрування на паролі),
а також сховище сертифікатів (`cert_store.h`).

## PKCS#12 (`pkcs12.h`)

Основний робочий формат: зберігає приватні ключі (захищені паролем)
і сертифікати. Цілісність захищається MAC на вибір
(`Pkcs12MacType`): ГОСТ 34.311 (`KS_FILE_PKCS12_WITH_GOST34311`),
SHA-1/224/256/384/512.

### Створення сховища та генерація ключа

```c
#include "pkcs12.h"
#include "aid.h"

Pkcs12Ctx *storage = NULL;
AlgorithmIdentifier_t *aid = NULL;
ByteArray *aid_ba = NULL;

/* алгоритм ключа — напр. ДСТУ 4145 з обраними параметрами */
aid_create_dstu4145(ec_params, cipher_params, true, &aid);
aid_encode(aid, &aid_ba);

pkcs12_create(KS_FILE_PKCS12_WITH_GOST34311, "пароль сховища", 1024 /* rounds */,
              &storage);
pkcs12_generate_key(storage, aid_ba);                    /* генерує ключову пару */
pkcs12_store_key(storage, "alias", "пароль ключа", 1024);
pkcs12_select_key(storage, "alias", "пароль ключа");     /* зробити активним */

ByteArray *body = NULL;
pkcs12_encode(storage, &body);       /* серіалізація */
ba_to_file(body, "key-6.dat");

pkcs12_free(storage);
```

### Відкриття сховища та використання ключа

Приватний ключ не віддається напряму — з активного ключа отримують
адаптери для шару PKI:

```c
Pkcs12Ctx *storage = NULL;
ByteArray *body = NULL;

ba_alloc_from_file("key-6.dat", &body);
pkcs12_decode(NULL, body, "пароль сховища", &storage);
pkcs12_select_key(storage, NULL, "пароль ключа");   /* NULL — перший ключ */

SignAdapter *sa = NULL;
pkcs12_get_sign_adapter(storage, &sa);     /* далі — підпис CMS/сертифікатів */
/* також: pkcs12_get_verify_adapter, pkcs12_get_dh_adapter */
```

### Сертифікати у сховищі

```c
const ByteArray *certs[2] = { cert_encoded, NULL };   /* NULL-термінований масив */
pkcs12_set_certificates(storage, certs);
/* читання: pkcs12_get_certificate(s) */
```

Інші операції: `pkcs12_enum_keys` (перелік ключів),
`pkcs12_change_password`, `pkcs12_get_storage_name`.

## PKCS#8 (`pkcs8.h`)

Низькорівневий контейнер приватного ключа (`PrivateKeyInfo_t`) — коли
потрібен саме ключ, а не сховище:

```c
#include "pkcs8.h"

PrivateKeyInfo_t *key = pkcs8_alloc();
pkcs8_decode(key, encoded_der);

Pkcs8PrivatekeyType type;
pkcs8_type(key, &type);      /* DSTU / RSA / DSA / ECDSA / GOST3410 */

/* адаптери безпосередньо з ключа: */
pkcs8_get_sign_adapter(key, ...);
pkcs8_get_verify_adapter(key, ...);
pkcs8_get_spki(key, ...);    /* відповідний відкритий ключ (SubjectPublicKeyInfo) */

pkcs8_free(key);
```

Генерація нового ключа: `pkcs8_generate(aid, &key)`;
серіалізація: `pkcs8_encode(key, &der)`.

## Безпека

- Паролі сховища та ключа можуть відрізнятися; кількість раундів
  хешування пароля (`rounds`, у прикладах 1024) збільшуйте відповідно
  до вимог до стійкості.
- Буфери з паролями та ключами звільняйте через `ba_free_private()`.

Повний сценарій (генерація ключа → випуск сертифіката → підпис) —
у `src/pkiExample/c/pki_example.c`.
