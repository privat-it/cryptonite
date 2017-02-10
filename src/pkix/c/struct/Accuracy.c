/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "Accuracy.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/Accuracy.c"

static int
memb_millis_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
        asn_app_constraint_failed_f *ctfailcb, void *app_key)
{
    long value;

    if (!sptr) {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: value not given (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }

    value = *(const long *)sptr;

    if ((value >= 1 && value <= 999)) {
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
memb_micros_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
        asn_app_constraint_failed_f *ctfailcb, void *app_key)
{
    long value;

    if (!sptr) {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: value not given (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }

    value = *(const long *)sptr;

    if ((value >= 1 && value <= 999)) {
        /* Constraint check succeeded */
        return 0;
    } else {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: constraint failed (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }
}

static asn_TYPE_member_t asn_MBR_Accuracy_1[] = {
    {
        ATF_POINTER, 3, offsetof(struct Accuracy, seconds),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "seconds"
    },
    {
        ATF_POINTER, 2, offsetof(struct Accuracy, millis),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &NativeInteger_desc,
        memb_millis_constraint_1,
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "millis"
    },
    {
        ATF_POINTER, 1, offsetof(struct Accuracy, micros),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &NativeInteger_desc,
        memb_micros_constraint_1,
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "micros"
    },
};
static const ber_tlv_tag_t Accuracy_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Accuracy_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }, /* seconds */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 }, /* millis */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 2, 0, 0 } /* micros */
};
static asn_SEQUENCE_specifics_t asn_SPC_Accuracy_specs_1 = {
    sizeof(struct Accuracy),
    offsetof(struct Accuracy, _asn_ctx),
    asn_MAP_Accuracy_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t Accuracy_desc = {
    "Accuracy",
    "Accuracy",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    Accuracy_desc_tags_1,
    sizeof(Accuracy_desc_tags_1)
    / sizeof(Accuracy_desc_tags_1[0]), /* 1 */
    Accuracy_desc_tags_1,    /* Same as above */
    sizeof(Accuracy_desc_tags_1)
    / sizeof(Accuracy_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_Accuracy_1,
    3,    /* Elements count */
    &asn_SPC_Accuracy_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_Accuracy_desc(void)
{
    return &Accuracy_desc;
}
