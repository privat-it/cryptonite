/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/*
 * Модуль реалізує роботу з набором розширень сертифіката/CRL (Extensions —
 * послідовність Extension). Надає створення набору, додавання розширення
 * (з копіюванням) та пошук розширення чи його значення за OID.
 */

#include "exts.h"

#include "pkix_macros_internal.h"
#include "log_internal.h"
#include "asn1_utils.h"
#include "pkix_utils.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/api/exts.c"

#define RND_BYTES 20

/* Виділяє пам'ять під порожній набір розширень. */
Extensions_t *exts_alloc(void)
{
    int ret = RET_OK;
    Extensions_t *exts = NULL;

    LOG_ENTRY();

    ASN_ALLOC(exts);

cleanup:

    return exts;
}

/* Додає копію розширення до набору. */
int exts_add_extension(Extensions_t *exts, const Extension_t *ext)
{
    int ret = RET_OK;
    Extension_t *ext_copy = NULL;

    LOG_ENTRY();

    CHECK_PARAM(exts != NULL);
    CHECK_PARAM(ext != NULL);

    CHECK_NOT_NULL(ext_copy = asn_copy_with_alloc(&Extension_desc, ext));
    DO(ASN_SEQUENCE_ADD(&exts->list, ext_copy));
    ext_copy = NULL;

cleanup:

    ASN_FREE(&Extension_desc, ext_copy);

    return ret;
}

/* Шукає розширення за OID і повертає його копію; інакше RET_PKIX_EXT_NOT_FOUND. */
int exts_get_ext_by_oid(const Extensions_t *exts, const OidNumbers *oid, Extension_t **ext)
{
    int ret = RET_OK;
    int i;

    LOG_ENTRY();

    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(ext != NULL);
    if (exts == NULL) {
        SET_ERROR(RET_PKIX_EXT_NOT_FOUND);
    }

    *ext = NULL;

    for (i = 0; i < exts->list.count; i++) {
        Extension_t *cur_ext = exts->list.array[i];

        if (!cur_ext) {
            continue;
        }

        if (pkix_check_oid_equal(&cur_ext->extnID, oid)) {
            CHECK_NOT_NULL(*ext = asn_copy_with_alloc(&Extension_desc, cur_ext));
            return RET_OK;
        }
    }

    SET_ERROR(RET_PKIX_EXT_NOT_FOUND);

cleanup:

    return ret;
}

/* Шукає розширення за OID і повертає його значення (extnValue) як ByteArray. */
int exts_get_ext_value_by_oid(const Extensions_t *exts, const OidNumbers *oid, ByteArray **value)
{
    int i;
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(exts != NULL);
    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(value != NULL);

    for (i = 0; i < exts->list.count; i++) {
        Extension_t *ext = exts->list.array[i];

        if (!ext) {
            continue;
        }

        if (pkix_check_oid_equal(&ext->extnID, oid)) {
            DO(asn_OCTSTRING2ba(&ext->extnValue, value));
            return RET_OK;
        }
    }

    SET_ERROR(RET_PKIX_EXT_NOT_FOUND);

cleanup:

    return ret;
}

/* Звільняє набір розширень. */
void exts_free(Extensions_t *exts)
{
    if (exts) {
        ASN_FREE(&Extensions_desc, exts);
    }
}
