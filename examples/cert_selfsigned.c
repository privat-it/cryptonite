/*
 * Приклад: випуск самопідписаного сертифіката X.509 (ДСТУ 4145).
 *
 * Потік: ключ у сховищі PKCS#12 → адаптер підпису → запит на
 * сертифікацію (CSR) → генератор сертифікатів → перевірка підпису.
 */

#include <stdio.h>
#include <time.h>

#include "aid.h"
#include "byte_array.h"
#include "cert.h"
#include "cert_engine.h"
#include "certification_request.h"
#include "certificate_request_engine.h"
#include "cryptonite_errors.h"
#include "cryptonite_manager.h"
#include "dstu4145.h"
#include "gost28147.h"
#include "pkcs12.h"
#include "spki.h"

#define PASSWORD "123456"
#define ROUNDS   1024

#define CHECK(func)                                                     \
    if ((ret = (func)) != RET_OK) {                                     \
        printf("Помилка %d у рядку %d\n", ret, __LINE__);               \
        goto cleanup;                                                   \
    }

int main(void)
{
    int ret = RET_OK;
    time_t not_before, not_after;
    const unsigned char serial[20] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14
    };

    Dstu4145Ctx *ec_params = NULL;
    Gost28147Ctx *cipher_params = NULL;
    AlgorithmIdentifier_t *aid = NULL;
    ByteArray *aid_ba = NULL;
    ByteArray *serial_ba = NULL;
    ByteArray *encoded = NULL;
    Pkcs12Ctx *storage = NULL;
    SignAdapter *sa = NULL;
    VerifyAdapter *va = NULL;
    DigestAdapter *da = NULL;
    SubjectPublicKeyInfo_t *spki = NULL;
    CertificateRequestEngine *req_eng = NULL;
    CertificationRequest_t *csr = NULL;
    CertificateEngine *cert_eng = NULL;
    Certificate_t *cert = NULL;

    /* 1. Ключова пара ДСТУ 4145 у сховищі PKCS#12. */
    ec_params = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);
    cipher_params = gost28147_alloc(GOST28147_SBOX_ID_1);
    CHECK(aid_create_dstu4145(ec_params, cipher_params, true, &aid));
    CHECK(aid_encode(aid, &aid_ba));
    CHECK(pkcs12_create(KS_FILE_PKCS12_WITH_GOST34311, PASSWORD, ROUNDS, &storage));
    CHECK(pkcs12_generate_key(storage, aid_ba));
    CHECK(pkcs12_store_key(storage, "ca", PASSWORD, ROUNDS));
    CHECK(pkcs12_select_key(storage, "ca", PASSWORD));

    /* 2. Адаптери: підпис із приватного ключа, хеш — за алгоритмом ключа. */
    CHECK(pkcs12_get_sign_adapter(storage, &sa));
    CHECK(sa->get_pub_key(sa, &spki));
    CHECK(digest_adapter_init_by_aid(&spki->algorithm, &da));

    /* 3. Запит на сертифікацію (CSR). */
    CHECK(ecert_request_alloc(sa, &req_eng));
    CHECK(ecert_request_set_subj_name(req_eng,
            "{O=Приклад}{CN=Тестовий ЦСК}{C=UA}"));
    CHECK(ecert_request_set_subj_alt_name(req_eng, "example.ua", "info@example.ua"));
    CHECK(ecert_request_generate(req_eng, &csr));
    printf("CSR згенеровано\n");

    /* 4. Випуск самопідписаного сертифіката (v3, чинність 10 років). */
    time(&not_before);
    not_after = not_before + (time_t)10 * 365 * 24 * 60 * 60;
    serial_ba = ba_alloc_from_uint8(serial, sizeof(serial));

    CHECK(ecert_alloc(sa, da, true /* самопідписаний */, &cert_eng));
    CHECK(ecert_generate(cert_eng, csr, 2 /* v3 */, serial_ba,
                         &not_before, &not_after, NULL /* без розширень */, &cert));
    printf("Сертифікат випущено\n");

    /* 5. Перевірка підпису та серіалізація в DER. */
    CHECK(pkcs12_get_verify_adapter(storage, &va));
    CHECK(cert_verify(cert, va));
    CHECK(cert_encode(cert, &encoded));
    printf("Підпис сертифіката коректний, DER: %u байтів\n",
           (unsigned)ba_get_len(encoded));
    /* далі зазвичай: ba_to_file(encoded, "certificate.cer"); */

cleanup:
    cert_free(cert);
    ecert_free(cert_eng);
    creq_free(csr);
    ecert_request_free(req_eng);
    spki_free(spki);
    sign_adapter_free(sa);
    verify_adapter_free(va);
    digest_adapter_free(da);
    pkcs12_free(storage);
    aid_free(aid);
    dstu4145_free(ec_params);
    gost28147_free(cipher_params);
    ba_free(aid_ba);
    ba_free(serial_ba);
    ba_free(encoded);
    return (ret == RET_OK) ? 0 : 1;
}
