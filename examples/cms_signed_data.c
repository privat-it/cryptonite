/*
 * Приклад: CMS-контейнер з підписаними даними (SignedData, .p7s).
 *
 * Потік: ключ + самопідписаний сертифікат → підписання даних
 * (signed_data_engine) → серіалізація ContentInfo у DER →
 * зворотне читання та перевірка підпису.
 */

#include <stdio.h>
#include <time.h>

#include "aid.h"
#include "asn1_utils.h"
#include "byte_array.h"
#include "cert.h"
#include "cert_engine.h"
#include "certification_request.h"
#include "certificate_request_engine.h"
#include "content_info.h"
#include "cryptonite_errors.h"
#include "cryptonite_manager.h"
#include "dstu4145.h"
#include "gost28147.h"
#include "oids.h"
#include "pkcs12.h"
#include "signed_data.h"
#include "signed_data_engine.h"
#include "signer_info_engine.h"
#include "spki.h"

#define PASSWORD "123456"
#define ROUNDS   1024

#define CHECK(func)                                                     \
    if ((ret = (func)) != RET_OK) {                                     \
        printf("Помилка %d у рядку %d\n", ret, __LINE__);               \
        goto cleanup;                                                   \
    }

/* Ключ у PKCS#12 + самопідписаний сертифікат (див. cert_selfsigned.c). */
static int make_key_and_cert(Pkcs12Ctx **storage, Certificate_t **cert)
{
    int ret = RET_OK;
    time_t not_before, not_after;
    const unsigned char serial[20] = { 0x42 };

    Dstu4145Ctx *ec_params = NULL;
    Gost28147Ctx *cipher_params = NULL;
    AlgorithmIdentifier_t *aid = NULL;
    ByteArray *aid_ba = NULL;
    ByteArray *serial_ba = NULL;
    SignAdapter *sa = NULL;
    DigestAdapter *da = NULL;
    SubjectPublicKeyInfo_t *spki = NULL;
    CertificateRequestEngine *req_eng = NULL;
    CertificationRequest_t *csr = NULL;
    CertificateEngine *cert_eng = NULL;

    ec_params = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);
    cipher_params = gost28147_alloc(GOST28147_SBOX_ID_1);
    CHECK(aid_create_dstu4145(ec_params, cipher_params, true, &aid));
    CHECK(aid_encode(aid, &aid_ba));
    CHECK(pkcs12_create(KS_FILE_PKCS12_WITH_GOST34311, PASSWORD, ROUNDS, storage));
    CHECK(pkcs12_generate_key(*storage, aid_ba));
    CHECK(pkcs12_store_key(*storage, "signer", PASSWORD, ROUNDS));
    CHECK(pkcs12_select_key(*storage, "signer", PASSWORD));

    CHECK(pkcs12_get_sign_adapter(*storage, &sa));
    CHECK(sa->get_pub_key(sa, &spki));
    CHECK(digest_adapter_init_by_aid(&spki->algorithm, &da));

    CHECK(ecert_request_alloc(sa, &req_eng));
    CHECK(ecert_request_set_subj_name(req_eng, "{O=Приклад}{CN=Підписувач}{C=UA}"));
    CHECK(ecert_request_set_subj_alt_name(req_eng, "example.ua", "signer@example.ua"));
    CHECK(ecert_request_generate(req_eng, &csr));

    time(&not_before);
    not_after = not_before + (time_t)365 * 24 * 60 * 60;
    serial_ba = ba_alloc_from_uint8(serial, sizeof(serial));
    CHECK(ecert_alloc(sa, da, true, &cert_eng));
    CHECK(ecert_generate(cert_eng, csr, 2, serial_ba, &not_before, &not_after,
                         NULL, cert));

cleanup:
    ecert_free(cert_eng);
    creq_free(csr);
    ecert_request_free(req_eng);
    spki_free(spki);
    sign_adapter_free(sa);
    digest_adapter_free(da);
    aid_free(aid);
    dstu4145_free(ec_params);
    gost28147_free(cipher_params);
    ba_free(aid_ba);
    ba_free(serial_ba);
    return ret;
}

int main(void)
{
    int ret = RET_OK;
    ByteArray *data = ba_alloc_from_str("Вміст документа, який підписуємо");
    ByteArray *p7s = NULL;
    Pkcs12Ctx *storage = NULL;
    Certificate_t *cert = NULL;
    SignAdapter *sa = NULL;
    DigestAdapter *da = NULL;
    SignerInfoEngine *si_eng = NULL;
    SignedDataEngine *sd_eng = NULL;
    SignedData_t *sdata = NULL;
    ContentInfo_t *container = NULL;

    /* --- Підготовка: ключ і сертифікат підписувача --- */
    CHECK(make_key_and_cert(&storage, &cert));
    printf("Ключ і сертифікат підписувача готові\n");

    /* --- Створення підпису --- */
    CHECK(pkcs12_get_sign_adapter(storage, &sa));
    CHECK(sa->set_cert(sa, cert));
    CHECK(digest_adapter_init_by_cert(cert, &da));

    CHECK(esigner_info_alloc(sa, da, NULL, &si_eng));
    CHECK(esigned_data_alloc(si_eng, &sd_eng));   /* si_eng переходить у власність sd_eng */
    si_eng = NULL;
    CHECK(esigned_data_set_data(sd_eng,
            oids_get_oid_numbers_by_id(OID_DATA_ID), data, true /* дані всередині */));
    CHECK(esigned_data_add_cert(sd_eng, cert));
    CHECK(esigned_data_generate(sd_eng, &sdata));

    container = cinfo_alloc();
    CHECK(cinfo_init_by_signed_data(container, sdata));
    CHECK(cinfo_encode(container, &p7s));
    printf("Контейнер .p7s створено: %u байтів\n", (unsigned)ba_get_len(p7s));
    /* далі зазвичай: ba_to_file(p7s, "document.p7s"); */

    /* --- Перевірка (як робив би отримувач, маючи лише p7s) --- */
    {
        ContentInfo_t *in_container = cinfo_alloc();
        SignedData_t *in_sdata = NULL;
        CertificateSet_t *certs = NULL;
        int i;

        CHECK(cinfo_decode(in_container, p7s));
        CHECK(cinfo_get_signed_data(in_container, &in_sdata));
        CHECK(sdata_get_certs(in_sdata, &certs));

        for (i = 0; i < certs->list.count; i++) {
            Certificate_t *c = &certs->list.array[i]->choice.certificate;
            DigestAdapter *vda = NULL;
            VerifyAdapter *va = NULL;

            CHECK(digest_adapter_init_by_cert(c, &vda));
            CHECK(verify_adapter_init_by_cert(c, &va));
            ret = sdata_verify_internal_data_by_adapter(in_sdata, vda, va, i);
            digest_adapter_free(vda);
            verify_adapter_free(va);
            CHECK(ret);
            printf("Підпис №%d перевірено — коректний\n", i);
        }

        ASN_FREE(get_CertificateSet_desc(), certs);
        sdata_free(in_sdata);
        cinfo_free(in_container);
    }

cleanup:
    cinfo_free(container);
    sdata_free(sdata);
    esigned_data_free(sd_eng);
    esigner_info_free(si_eng);
    digest_adapter_free(da);
    sign_adapter_free(sa);
    cert_free(cert);
    pkcs12_free(storage);
    ba_free(data);
    ba_free(p7s);
    return (ret == RET_OK) ? 0 : 1;
}
