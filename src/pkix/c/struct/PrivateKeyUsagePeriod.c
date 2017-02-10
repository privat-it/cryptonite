/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "PrivateKeyUsagePeriod.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/PrivateKeyUsagePeriod.c"

static asn_TYPE_member_t asn_MBR_PrivateKeyUsagePeriod_1[] = {
    {
        ATF_POINTER, 2, offsetof(struct PrivateKeyUsagePeriod, notBefore),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &GeneralizedTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "notBefore"
    },
    {
        ATF_POINTER, 1, offsetof(struct PrivateKeyUsagePeriod, notAfter),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &GeneralizedTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "notAfter"
    },
};
static const ber_tlv_tag_t PrivateKeyUsagePeriod_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PrivateKeyUsagePeriod_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* notBefore */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* notAfter */
};
static asn_SEQUENCE_specifics_t asn_SPC_PrivateKeyUsagePeriod_specs_1 = {
    sizeof(struct PrivateKeyUsagePeriod),
    offsetof(struct PrivateKeyUsagePeriod, _asn_ctx),
    asn_MAP_PrivateKeyUsagePeriod_tag2el_1,
    2,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t PrivateKeyUsagePeriod_desc = {
    "PrivateKeyUsagePeriod",
    "PrivateKeyUsagePeriod",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    PrivateKeyUsagePeriod_desc_tags_1,
    sizeof(PrivateKeyUsagePeriod_desc_tags_1)
    / sizeof(PrivateKeyUsagePeriod_desc_tags_1[0]), /* 1 */
    PrivateKeyUsagePeriod_desc_tags_1,    /* Same as above */
    sizeof(PrivateKeyUsagePeriod_desc_tags_1)
    / sizeof(PrivateKeyUsagePeriod_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_PrivateKeyUsagePeriod_1,
    2,    /* Elements count */
    &asn_SPC_PrivateKeyUsagePeriod_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_PrivateKeyUsagePeriod_desc(void)
{
    return &PrivateKeyUsagePeriod_desc;
}
