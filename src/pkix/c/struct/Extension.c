/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "Extension.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/Extension.c"

static asn_TYPE_member_t asn_MBR_Extension_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct Extension, extnID),
        (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
        0,
        &OBJECT_IDENTIFIER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "extnID"
    },
    {
        ATF_POINTER, 1, offsetof(struct Extension, critical),
        (ASN_TAG_CLASS_UNIVERSAL | (1 << 2)),
        0,
        &BOOLEAN_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "critical"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct Extension, extnValue),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &OCTET_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "extnValue"
    },
};
static const ber_tlv_tag_t Extension_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Extension_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (1 << 2)), 1, 0, 0 }, /* critical */
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 2, 0, 0 }, /* extnValue */
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 0, 0, 0 } /* extnID */
};
static asn_SEQUENCE_specifics_t asn_SPC_Extension_specs_1 = {
    sizeof(struct Extension),
    offsetof(struct Extension, _asn_ctx),
    asn_MAP_Extension_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t Extension_desc = {
    "Extension",
    "Extension",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    Extension_desc_tags_1,
    sizeof(Extension_desc_tags_1)
    / sizeof(Extension_desc_tags_1[0]), /* 1 */
    Extension_desc_tags_1,    /* Same as above */
    sizeof(Extension_desc_tags_1)
    / sizeof(Extension_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_Extension_1,
    3,    /* Elements count */
    &asn_SPC_Extension_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_Extension_desc(void)
{
    return &Extension_desc;
}
