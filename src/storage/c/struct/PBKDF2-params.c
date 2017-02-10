/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "PBKDF2-params.h"

#include "asn_internal.h"

#include "AlgorithmIdentifier.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/PBKDF2-params.c"

static int
memb_iterationCount_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
        asn_app_constraint_failed_f *ctfailcb, void *app_key)
{
    const INTEGER_t *st = (const INTEGER_t *)sptr;
    long value;

    if (!sptr) {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: value not given (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }

    if (asn_INTEGER2long(st, &value)) {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: value too large (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }

    if ((value >= 1)) {
        /* Constraint check succeeded */
        return 0;
    } else {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: constraint failed (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }
}

static int
memb_keyLength_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
        asn_app_constraint_failed_f *ctfailcb, void *app_key)
{
    const INTEGER_t *st = (const INTEGER_t *)sptr;
    long value;

    if (!sptr) {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: value not given (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }

    if (asn_INTEGER2long(st, &value)) {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: value too large (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }

    if ((value >= 1)) {
        /* Constraint check succeeded */
        return 0;
    } else {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: constraint failed (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }
}

static asn_TYPE_member_t asn_MBR_PBKDF2_params_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct PBKDF2_params, salt),
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &PBKDF2_Salt_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "salt"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct PBKDF2_params, iterationCount),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        memb_iterationCount_constraint_1,
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "iterationCount"
    },
    {
        ATF_POINTER, 2, offsetof(struct PBKDF2_params, keyLength),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        memb_keyLength_constraint_1,
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "keyLength"
    },
    {
        ATF_POINTER, 1, offsetof(struct PBKDF2_params, prf),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &AlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "prf"
    },
};
static const ber_tlv_tag_t PBKDF2_params_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PBKDF2_params_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 1, 0, 1 }, /* iterationCount */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 2, -1, 0 }, /* keyLength */
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, 0, 0 }, /* specified */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 1 }, /* otherSource */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 3, -1, 0 } /* prf */
};
static asn_SEQUENCE_specifics_t asn_SPC_PBKDF2_params_specs_1 = {
    sizeof(struct PBKDF2_params),
    offsetof(struct PBKDF2_params, _asn_ctx),
    asn_MAP_PBKDF2_params_tag2el_1,
    5,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t PBKDF2_params_desc = {
    "PBKDF2-params",
    "PBKDF2-params",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    PBKDF2_params_desc_tags_1,
    sizeof(PBKDF2_params_desc_tags_1)
    / sizeof(PBKDF2_params_desc_tags_1[0]), /* 1 */
    PBKDF2_params_desc_tags_1,    /* Same as above */
    sizeof(PBKDF2_params_desc_tags_1)
    / sizeof(PBKDF2_params_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_PBKDF2_params_1,
    4,    /* Elements count */
    &asn_SPC_PBKDF2_params_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_PBKDF2_params_desc(void)
{
    return &PBKDF2_params_desc;
}
