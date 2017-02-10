/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "CertificationRequest.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/CertificationRequest.c"

static asn_TYPE_member_t asn_MBR_CertificationRequest_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificationRequest, certificationRequestInfo),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &CertificationRequestInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "certificationRequestInfo"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificationRequest, signatureAlgorithm),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &AlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signatureAlgorithm"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificationRequest, signature),
        (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)),
        0,
        &BIT_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signature"
    },
};
static const ber_tlv_tag_t CertificationRequest_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CertificationRequest_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)), 2, 0, 0 }, /* signature */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 1 }, /* certificationRequestInfo */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, -1, 0 } /* signatureAlgorithm */
};
static asn_SEQUENCE_specifics_t asn_SPC_CertificationRequest_specs_1 = {
    sizeof(struct CertificationRequest),
    offsetof(struct CertificationRequest, _asn_ctx),
    asn_MAP_CertificationRequest_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t CertificationRequest_desc = {
    "CertificationRequest",
    "CertificationRequest",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    CertificationRequest_desc_tags_1,
    sizeof(CertificationRequest_desc_tags_1)
    / sizeof(CertificationRequest_desc_tags_1[0]), /* 1 */
    CertificationRequest_desc_tags_1,    /* Same as above */
    sizeof(CertificationRequest_desc_tags_1)
    / sizeof(CertificationRequest_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_CertificationRequest_1,
    3,    /* Elements count */
    &asn_SPC_CertificationRequest_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_CertificationRequest_desc(void)
{
    return &CertificationRequest_desc;
}
