/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "MacData.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/MacData.c"

static int asn_DFL_4_set_1(int set_value, void **sptr)
{
    INTEGER_t *st = *sptr;

    if (!st) {
        if (!set_value) {
            return -1;    /* Not a default value */
        }
        st = (*sptr = CALLOC(1, sizeof(*st)));
        if (!st) {
            return -1;
        }
    }

    if (set_value) {
        /* Install default value 1 */
        return asn_long2INTEGER(st, 1);
    } else {
        /* Test default value 1 */
        long value;
        if (asn_INTEGER2long(st, &value)) {
            return -1;
        }
        return (value == 1);
    }
}
static asn_TYPE_member_t asn_MBR_MacData_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct MacData, mac),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &DigestInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "mac"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct MacData, macSalt),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &OCTET_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "macSalt"
    },
    {
        ATF_POINTER, 1, offsetof(struct MacData, iterations),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        asn_DFL_4_set_1,    /* DEFAULT 1 */
        "iterations"
    },
};
static const ber_tlv_tag_t MacData_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MacData_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 2, 0, 0 }, /* iterations */
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 1, 0, 0 }, /* macSalt */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 } /* mac */
};
static asn_SEQUENCE_specifics_t asn_SPC_MacData_specs_1 = {
    sizeof(struct MacData),
    offsetof(struct MacData, _asn_ctx),
    asn_MAP_MacData_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t MacData_desc = {
    "MacData",
    "MacData",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    MacData_desc_tags_1,
    sizeof(MacData_desc_tags_1)
    / sizeof(MacData_desc_tags_1[0]), /* 1 */
    MacData_desc_tags_1,    /* Same as above */
    sizeof(MacData_desc_tags_1)
    / sizeof(MacData_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_MacData_1,
    3,    /* Elements count */
    &asn_SPC_MacData_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_MacData_desc(void)
{
    return &MacData_desc;
}
