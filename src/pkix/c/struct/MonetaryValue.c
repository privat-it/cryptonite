/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "MonetaryValue.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/MonetaryValue.c"

static asn_TYPE_member_t asn_MBR_MonetaryValue_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct MonetaryValue, currency),
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &Iso4217CurrencyCode_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "currency"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct MonetaryValue, amount),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "amount"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct MonetaryValue, exponent),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "exponent"
    },
};
static const ber_tlv_tag_t MonetaryValue_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MonetaryValue_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 2 }, /* numeric */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 1, -1, 1 }, /* amount */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 2, -2, 0 }, /* exponent */
    { (ASN_TAG_CLASS_UNIVERSAL | (19 << 2)), 0, 0, 0 } /* alphabetic */
};
static asn_SEQUENCE_specifics_t asn_SPC_MonetaryValue_specs_1 = {
    sizeof(struct MonetaryValue),
    offsetof(struct MonetaryValue, _asn_ctx),
    asn_MAP_MonetaryValue_tag2el_1,
    4,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t MonetaryValue_desc = {
    "MonetaryValue",
    "MonetaryValue",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    MonetaryValue_desc_tags_1,
    sizeof(MonetaryValue_desc_tags_1)
    / sizeof(MonetaryValue_desc_tags_1[0]), /* 1 */
    MonetaryValue_desc_tags_1,    /* Same as above */
    sizeof(MonetaryValue_desc_tags_1)
    / sizeof(MonetaryValue_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_MonetaryValue_1,
    3,    /* Elements count */
    &asn_SPC_MonetaryValue_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_MonetaryValue_desc(void)
{
    return &MonetaryValue_desc;
}
