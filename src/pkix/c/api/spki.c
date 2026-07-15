/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/*
 * Модуль реалізує роботу зі структурою SubjectPublicKeyInfo (RFC 5280) —
 * контейнером відкритого ключа, який містить ідентифікатор алгоритму та
 * власне значення відкритого ключа. Надає створення/звільнення об'єкта,
 * ASN.1 кодування/декодування та витягання "сирого" відкритого ключа.
 */

#include "spki.h"

#include "pkix_utils.h"
#include "asn1_utils.h"
#include "pkix_macros_internal.h"
#include "log_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/api/spki.c"

/* Виділяє пам'ять під порожній об'єкт SubjectPublicKeyInfo. */
SubjectPublicKeyInfo_t *spki_alloc(void)
{
    SubjectPublicKeyInfo_t *spki = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    ASN_ALLOC(spki);

cleanup:

    return spki;
}

/* Звільняє об'єкт SubjectPublicKeyInfo. */
void spki_free(SubjectPublicKeyInfo_t *spki)
{
    LOG_ENTRY();

    ASN_FREE(&SubjectPublicKeyInfo_desc, spki);
}

/* Кодує SubjectPublicKeyInfo у DER-подання (ByteArray). */
int spki_encode(const SubjectPublicKeyInfo_t *spki, ByteArray **out)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(spki != NULL);
    CHECK_PARAM(out != NULL);

    DO(asn_encode_ba(&SubjectPublicKeyInfo_desc, spki, out));

cleanup:

    return ret;
}

/* Декодує SubjectPublicKeyInfo з DER-подання; попередній вміст очищується. */
int spki_decode(SubjectPublicKeyInfo_t *spki, const ByteArray *in)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(spki != NULL);
    CHECK_PARAM(in != NULL);

    ASN_FREE_CONTENT_PTR(&SubjectPublicKeyInfo_desc, spki);

    DO(asn_decode_ba(&SubjectPublicKeyInfo_desc, spki, in));

cleanup:

    return ret;
}

/*
 * Витягає "сире" значення відкритого ключа з SubjectPublicKeyInfo.
 * Для ДСТУ 4145 ключ береться як OCTET STRING (для BE-параметрів байти
 * переставляються), для EC-ключа — безпосередньо з бітового рядка.
 */
int spki_get_pub_key(const SubjectPublicKeyInfo_t *spki, ByteArray **pub_key)
{
    int ret = RET_OK;

    ByteArray *key = NULL;
    ByteArray *buffer = NULL;

    OCTET_STRING_t *os_key = NULL;

    LOG_ENTRY();

    CHECK_PARAM(spki != NULL);
    CHECK_PARAM(pub_key != NULL);

    ASN_ALLOC(os_key);

    DO(asn_BITSTRING2ba(&spki->subjectPublicKey, &buffer));

    if (pkix_check_oid_parent(&spki->algorithm.algorithm, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID))) {

        DO(asn_decode_ba(&OCTET_STRING_desc, os_key, buffer));
        DO(asn_OCTSTRING2ba(os_key, &key));

        if (is_dstu_be_params(&spki->algorithm.algorithm)) {
            DO(ba_swap(key));
        }
    } else if (pkix_check_oid_parent(&spki->algorithm.algorithm, oids_get_oid_numbers_by_id(OID_EC_PUBLIC_KEY_TYPE_ID))) {
        ASN_FREE(&BIT_STRING_desc, os_key);
        os_key = NULL;

        DO(asn_create_octstring_from_ba(buffer, &os_key));
        DO(asn_OCTSTRING2ba(os_key, &key));

    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_SPKI_ALG);
    }

    *pub_key = key;

cleanup:

    ba_free(buffer);
    ASN_FREE(&OCTET_STRING_desc, os_key);

    if (ret != RET_OK) {
        ba_free_private(key);
    }

    return ret;
}
