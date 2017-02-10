/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "BuiltInDomainDefinedAttribute.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/BuiltInDomainDefinedAttribute.c"

static asn_TYPE_member_t asn_MBR_BuiltInDomainDefinedAttribute_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct BuiltInDomainDefinedAttribute, type),
        (ASN_TAG_CLASS_UNIVERSAL | (19 << 2)),
        0,
        &PrintableString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "type"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct BuiltInDomainDefinedAttribute, value),
        (ASN_TAG_CLASS_UNIVERSAL | (19 << 2)),
        0,
        &PrintableString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "value"
    },
};
static const ber_tlv_tag_t BuiltInDomainDefinedAttribute_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_BuiltInDomainDefinedAttribute_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (19 << 2)), 0, 0, 1 }, /* type */
    { (ASN_TAG_CLASS_UNIVERSAL | (19 << 2)), 1, -1, 0 } /* value */
};
static asn_SEQUENCE_specifics_t asn_SPC_BuiltInDomainDefinedAttribute_specs_1 = {
    sizeof(struct BuiltInDomainDefinedAttribute),
    offsetof(struct BuiltInDomainDefinedAttribute, _asn_ctx),
    asn_MAP_BuiltInDomainDefinedAttribute_tag2el_1,
    2,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t BuiltInDomainDefinedAttribute_desc = {
    "BuiltInDomainDefinedAttribute",
    "BuiltInDomainDefinedAttribute",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    BuiltInDomainDefinedAttribute_desc_tags_1,
    sizeof(BuiltInDomainDefinedAttribute_desc_tags_1)
    / sizeof(BuiltInDomainDefinedAttribute_desc_tags_1[0]), /* 1 */
    BuiltInDomainDefinedAttribute_desc_tags_1,    /* Same as above */
    sizeof(BuiltInDomainDefinedAttribute_desc_tags_1)
    / sizeof(BuiltInDomainDefinedAttribute_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_BuiltInDomainDefinedAttribute_1,
    2,    /* Elements count */
    &asn_SPC_BuiltInDomainDefinedAttribute_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_BuiltInDomainDefinedAttribute_desc(void)
{
    return &BuiltInDomainDefinedAttribute_desc;
}
