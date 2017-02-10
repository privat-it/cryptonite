/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "CertificateList.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/CertificateList.c"

static asn_TYPE_member_t asn_MBR_CertificateList_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificateList, tbsCertList),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &TBSCertList_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "tbsCertList"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificateList, signatureAlgorithm),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &AlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signatureAlgorithm"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificateList, signatureValue),
        (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)),
        0,
        &BIT_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signatureValue"
    },
};
static const ber_tlv_tag_t CertificateList_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CertificateList_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)), 2, 0, 0 }, /* signatureValue */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 1 }, /* tbsCertList */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, -1, 0 } /* signatureAlgorithm */
};
static asn_SEQUENCE_specifics_t asn_SPC_CertificateList_specs_1 = {
    sizeof(struct CertificateList),
    offsetof(struct CertificateList, _asn_ctx),
    asn_MAP_CertificateList_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t CertificateList_desc = {
    "CertificateList",
    "CertificateList",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    CertificateList_desc_tags_1,
    sizeof(CertificateList_desc_tags_1)
    / sizeof(CertificateList_desc_tags_1[0]), /* 1 */
    CertificateList_desc_tags_1,    /* Same as above */
    sizeof(CertificateList_desc_tags_1)
    / sizeof(CertificateList_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_CertificateList_1,
    3,    /* Elements count */
    &asn_SPC_CertificateList_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_CertificateList_desc(void)
{
    return &CertificateList_desc;
}
