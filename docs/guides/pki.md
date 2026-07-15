# Сертифікати та PKI

Шар `pkix` працює на двох рівнях:

- **ASN.1-структури** (суфікс `_t`: `Certificate_t`, `SignedData_t`,
  `OCSPRequest_t`…) з однаковим життєвим циклом:
  `<x>_alloc()` → `<x>_decode(obj, ba)` / `<x>_encode(obj, &ba)` → `<x>_free(obj)`;
- **движки** (engine, префікс `e`: `ecert_*`, `esigned_data_*`, `ecrl_*`…),
  які будують ці структури.

Криптографію їм постачають **адаптери** — абстракція над ключами й
алгоритмами.

## Адаптери (`cryptonite_manager.h`)

```c
DigestAdapter *da = NULL;
VerifyAdapter *va = NULL;
SignAdapter   *sa = NULL;
DhAdapter    *dha = NULL;

digest_adapter_init_default(&da);            /* хеш за замовчуванням (ГОСТ 34.311) */
digest_adapter_init_by_cert(cert, &da);      /* за алгоритмом із сертифіката */
verify_adapter_init_by_cert(cert, &va);      /* відкритий ключ із сертифіката */

/* адаптери з приватним ключем — із ключового сховища PKCS#12: */
pkcs12_get_sign_adapter(storage, &sa);
pkcs12_get_dh_adapter(storage, &dha);

sa->set_cert(sa, cert);                      /* прив'язати сертифікат підписувача */

/* звільнення: digest_adapter_free(da); verify_adapter_free(va); ... */
```

## Сертифікати X.509

### Читання та перевірка

```c
#include "cert.h"

Certificate_t *cert = cert_alloc();
cert_decode(cert, encoded_der);              /* ByteArray з DER */

/* поля доступні напряму: cert->tbsCertificate.validity, ->serialNumber, ->issuer */

VerifyAdapter *va = NULL;
verify_adapter_init_by_cert(issuer_cert, &va);
int ret = cert_verify(cert, va);             /* RET_OK — підпис емітента коректний */

verify_adapter_free(va);
cert_free(cert);
```

### Запит на сертифікацію (CSR)

```c
#include "certificate_request_engine.h"

CertificateRequestEngine *eng = NULL;
CertificationRequest_t *csr = NULL;

ecert_request_alloc(sa, &eng);                       /* sa — SignAdapter заявника */
ecert_request_set_subj_name(eng, "{O=Компанія}{CN=Ім'я}{C=UA}");
ecert_request_set_subj_alt_name(eng, dns, email);
ecert_request_generate(eng, &csr);
creq_encode(csr, &encoded);                          /* DER */

ecert_request_free(eng);
```

### Випуск сертифіката

```c
#include "cert_engine.h"
#include "exts.h"
#include "ext.h"

/* розширення */
Extensions_t *exts = exts_alloc();
/* ext_create_key_usage / ext_create_basic_constraints / ext_create_subj_key_id /
   ext_create_auth_key_id_from_cert / ext_create_cert_policies / ... */
exts_add_extension(exts, ext);

CertificateEngine *eng = NULL;
Certificate_t *new_cert = NULL;

ecert_alloc(sa, da, false /* is_self_signed */, &eng);
ecert_generate(eng, csr, 2 /* v3 */, serial_ba, &not_before, &not_after,
               exts, &new_cert);
cert_encode(new_cert, &encoded);

ecert_free(eng);
```

## CMS: підписані дані (SignedData, .p7s)

### Створення підпису

```c
#include "signer_info_engine.h"
#include "signed_data_engine.h"
#include "content_info.h"

SignerInfoEngine *si = NULL;
SignedDataEngine *sd = NULL;
SignedData_t *sdata = NULL;
ContentInfo_t *container = NULL;

digest_adapter_init_by_cert(cert, &da);
sa->set_cert(sa, cert);

esigner_info_alloc(sa, da, NULL, &si);
esigned_data_alloc(si, &sd);
esigned_data_set_data(sd, oids_get_oid_numbers_by_id(OID_DATA_ID), data, true);
esigned_data_add_cert(sd, cert);              /* вкласти сертифікат у контейнер */
esigned_data_generate(sd, &sdata);

container = cinfo_alloc();
cinfo_init_by_signed_data(container, sdata);
cinfo_encode(container, &p7s);                /* готовий .p7s */
```

### Перевірка підпису

```c
ContentInfo_t *container = cinfo_alloc();
SignedData_t *sdata = NULL;
CertificateSet_t *certs = NULL;

cinfo_decode(container, p7s);
cinfo_get_signed_data(container, &sdata);
sdata_get_certs(sdata, &certs);

for (int i = 0; i < certs->list.count; i++) {
    Certificate_t *c = &certs->list.array[i]->choice.certificate;
    digest_adapter_init_default(&da);
    verify_adapter_init_by_cert(c, &va);
    sdata_verify_internal_data_by_adapter(sdata, da, va, i);   /* RET_OK — ок */
}
```

Формат CAdES підписувача: `sdata_get_signer_info_by_idx` +
`sinfo_get_format` (`CADES_BES_FORMAT`, `CADES_EPES_FORMAT`,
`CADES_C_FORMAT`, `CADES_X_FORMAT`).

## CMS: зашифровані дані (EnvelopedData)

Шифрування для отримувача за його сертифікатом (узгодження ключів
Діффі-Хеллмана):

```c
#include "enveloped_data_engine.h"

EnvelopedDataEngine *eng = NULL;
EnvelopedData_t *edata = NULL;
ByteArray *encrypted = NULL;

eenvel_data_alloc(sender_dha, &eng);                 /* DhAdapter відправника */
pkix_create_oid(oids_get_oid_numbers_by_id(OID_DATA_ID), &oid_data);
eenvel_data_set_data(eng, oid_data, data);
eenvel_data_set_originator_cert(eng, sender_cert);
eenvel_data_set_encription_oid(eng, cipher_oid);     /* напр. OID_GOST28147_CFB_ID */
eenvel_data_add_recipient(eng, recipient_cert);
eenvel_data_set_prng(eng, prng);
eenvel_data_generate(eng, &edata, &encrypted);
```

Розшифрування — одним викликом:

```c
env_decrypt_data(edata, NULL, sender_cert, recipient_dha, recipient_cert,
                 &decrypted);
```

## CRL

```c
#include "crl_engine.h"

CrlEngine *eng = NULL;
CertificateList_t *crl = NULL;

/* повний список: 1-й аргумент NULL; дельта: передати повний CRL і CRL_DELTA */
ecrl_alloc(NULL, sa, va, exts, "templ", CRL_FULL, descr, &eng);
ecrl_add_revoked_cert_by_sn(eng, cert_sn, reason, &revoke_time);
ecrl_generate_diff_next_update(eng, 60*60*24*7, &crl);   /* чинність, сек */
crl_encode(crl, &encoded);

ecrl_free(eng);
```

## OCSP і TSP

**OCSP-запит** — `eocspreq_alloc(has_nonce, root_va, ocsp_va, sa, da, &eng)` →
`eocspreq_add_cert(eng, cert)` → `eocspreq_generate(eng, nonce, &request)`.

**OCSP-відповідь** — `eocspresp_alloc(root_va, ocsp_sa, crls, da, …,
OCSP_RESPONSE_BY_HASH_KEY, &ctx)` → `eocspresp_generate(ctx, request, req_va,
time, &response)`.

**TSP-запит** — `etspreq_generate(da, data, NULL, policy_oid, true, &request)`
(політики: `OID_PKI_TSP_POLICY_DSTU_PB_ID` / `..._ONB_ID`).

**TSP-відповідь** — через мапу адаптерів: `adapters_map_alloc()` →
`adapters_map_add(map, da, sa)` → `etspresp_generate(map, request, serial,
digest_algs, &time, &response)`; мітка часу — `tsresp_get_ts_token`.

## Повний приклад

`src/pkiExample/c/pki_example.c` — самодостатній генератор тестової PKI:
створює кореневий та користувацькі сертифікати, CRL, OCSP/TSP-обміни,
CMS-контейнери для всіх 15 наборів параметрів ДСТУ 4145 і зберігає їх у
`build/tmp/pkiExample/`.
