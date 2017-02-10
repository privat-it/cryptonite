/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "SignerInfo.h"

#include "asn_internal.h"

#include "SignedAttributes.h"
#include "UnsignedAttributes.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/SignerInfo.c"

static asn_TYPE_member_t asn_MBR_SignerInfo_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct SignerInfo, version),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &CMSVersion_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "version"
    },
    {
        ATF_OPEN_TYPE | ATF_NOFLAGS, 0, offsetof(struct SignerInfo, sid),
        -1 /* Ambiguous tag (ANY?) */,
        0,
        &SignerIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "sid"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct SignerInfo, digestAlgorithm),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &DigestAlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "digestAlgorithm"
    },
    {
        ATF_POINTER, 1, offsetof(struct SignerInfo, signedAttrs),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &SignedAttributes_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signedAttrs"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct SignerInfo, signatureAlgorithm),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &SignatureAlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signatureAlgorithm"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct SignerInfo, signature),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &OCTET_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signature"
    },
    {
        ATF_POINTER, 1, offsetof(struct SignerInfo, unsignedAttrs),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &UnsignedAttributes_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "unsignedAttrs"
    },
};
static const ber_tlv_tag_t SignerInfo_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SignerInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 5, 0, 0 }, /* signature */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, 0, 1 }, /* digestAlgorithm */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 4, -1, 0 }, /* signatureAlgorithm */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 3, 0, 0 }, /* signedAttrs */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 6, 0, 0 } /* unsignedAttrs */
};
static asn_SEQUENCE_specifics_t asn_SPC_SignerInfo_specs_1 = {
    sizeof(struct SignerInfo),
    offsetof(struct SignerInfo, _asn_ctx),
    asn_MAP_SignerInfo_tag2el_1,
    6,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t SignerInfo_desc = {
    "SignerInfo",
    "SignerInfo",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    SignerInfo_desc_tags_1,
    sizeof(SignerInfo_desc_tags_1)
    / sizeof(SignerInfo_desc_tags_1[0]), /* 1 */
    SignerInfo_desc_tags_1,    /* Same as above */
    sizeof(SignerInfo_desc_tags_1)
    / sizeof(SignerInfo_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_SignerInfo_1,
    7,    /* Elements count */
    &asn_SPC_SignerInfo_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_SignerInfo_desc(void)
{
    return &SignerInfo_desc;
}
