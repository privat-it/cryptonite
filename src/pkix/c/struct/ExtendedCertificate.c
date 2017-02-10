/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "ExtendedCertificate.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/ExtendedCertificate.c"

static asn_TYPE_member_t asn_MBR_ExtendedCertificate_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct ExtendedCertificate, extendedCertificateInfo),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &ExtendedCertificateInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "extendedCertificateInfo"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct ExtendedCertificate, signatureAlgorithm),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &SignatureAlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signatureAlgorithm"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct ExtendedCertificate, signature),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &Signature_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signature"
    },
};
static const ber_tlv_tag_t ExtendedCertificate_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ExtendedCertificate_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 2 }, /* extendedCertificateInfo */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, -1, 1 }, /* signatureAlgorithm */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, -2, 0 } /* signature */
};
static asn_SEQUENCE_specifics_t asn_SPC_ExtendedCertificate_specs_1 = {
    sizeof(struct ExtendedCertificate),
    offsetof(struct ExtendedCertificate, _asn_ctx),
    asn_MAP_ExtendedCertificate_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t ExtendedCertificate_desc = {
    "ExtendedCertificate",
    "ExtendedCertificate",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    ExtendedCertificate_desc_tags_1,
    sizeof(ExtendedCertificate_desc_tags_1)
    / sizeof(ExtendedCertificate_desc_tags_1[0]), /* 1 */
    ExtendedCertificate_desc_tags_1,    /* Same as above */
    sizeof(ExtendedCertificate_desc_tags_1)
    / sizeof(ExtendedCertificate_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_ExtendedCertificate_1,
    3,    /* Elements count */
    &asn_SPC_ExtendedCertificate_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_ExtendedCertificate_desc(void)
{
    return &ExtendedCertificate_desc;
}
