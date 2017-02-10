/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "EncryptedData.h"

#include "asn_internal.h"

#include "UnprotectedAttributes.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/EncryptedData.c"

static asn_TYPE_member_t asn_MBR_EncryptedData_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct EncryptedData, version),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &CMSVersion_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "version"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct EncryptedData, encryptedContentInfo),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &EncryptedContentInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "encryptedContentInfo"
    },
    {
        ATF_POINTER, 1, offsetof(struct EncryptedData, unprotectedAttrs),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &UnprotectedAttributes_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "unprotectedAttrs"
    },
};
static const ber_tlv_tag_t EncryptedData_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_EncryptedData_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 0 }, /* encryptedContentInfo */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 2, 0, 0 } /* unprotectedAttrs */
};
static asn_SEQUENCE_specifics_t asn_SPC_EncryptedData_specs_1 = {
    sizeof(struct EncryptedData),
    offsetof(struct EncryptedData, _asn_ctx),
    asn_MAP_EncryptedData_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t EncryptedData_desc = {
    "EncryptedData",
    "EncryptedData",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    EncryptedData_desc_tags_1,
    sizeof(EncryptedData_desc_tags_1)
    / sizeof(EncryptedData_desc_tags_1[0]), /* 1 */
    EncryptedData_desc_tags_1,    /* Same as above */
    sizeof(EncryptedData_desc_tags_1)
    / sizeof(EncryptedData_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_EncryptedData_1,
    3,    /* Elements count */
    &asn_SPC_EncryptedData_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_EncryptedData_desc(void)
{
    return &EncryptedData_desc;
}
