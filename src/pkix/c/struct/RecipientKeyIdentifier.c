/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "RecipientKeyIdentifier.h"

#include "asn_internal.h"

#include "OtherKeyAttribute.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/RecipientKeyIdentifier.c"

static asn_TYPE_member_t asn_MBR_RecipientKeyIdentifier_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct RecipientKeyIdentifier, subjectKeyIdentifier),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &SubjectKeyIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "subjectKeyIdentifier"
    },
    {
        ATF_POINTER, 2, offsetof(struct RecipientKeyIdentifier, date),
        (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)),
        0,
        &GeneralizedTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "date"
    },
    {
        ATF_POINTER, 1, offsetof(struct RecipientKeyIdentifier, other),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &OtherKeyAttribute_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "other"
    },
};
static const ber_tlv_tag_t RecipientKeyIdentifier_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RecipientKeyIdentifier_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, 0, 0 }, /* subjectKeyIdentifier */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, 0, 0 }, /* other */
    { (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)), 1, 0, 0 } /* date */
};
static asn_SEQUENCE_specifics_t asn_SPC_RecipientKeyIdentifier_specs_1 = {
    sizeof(struct RecipientKeyIdentifier),
    offsetof(struct RecipientKeyIdentifier, _asn_ctx),
    asn_MAP_RecipientKeyIdentifier_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t RecipientKeyIdentifier_desc = {
    "RecipientKeyIdentifier",
    "RecipientKeyIdentifier",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    RecipientKeyIdentifier_desc_tags_1,
    sizeof(RecipientKeyIdentifier_desc_tags_1)
    / sizeof(RecipientKeyIdentifier_desc_tags_1[0]), /* 1 */
    RecipientKeyIdentifier_desc_tags_1,    /* Same as above */
    sizeof(RecipientKeyIdentifier_desc_tags_1)
    / sizeof(RecipientKeyIdentifier_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_RecipientKeyIdentifier_1,
    3,    /* Elements count */
    &asn_SPC_RecipientKeyIdentifier_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_RecipientKeyIdentifier_desc(void)
{
    return &RecipientKeyIdentifier_desc;
}
