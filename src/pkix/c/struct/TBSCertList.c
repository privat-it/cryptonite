/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "TBSCertList.h"

#include "asn_internal.h"

#include "RevokedCertificates.h"
#include "Extensions.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/TBSCertList.c"

static asn_TYPE_member_t asn_MBR_TBSCertList_1[] = {
    {
        ATF_POINTER, 1, offsetof(struct TBSCertList, version),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &Version_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "version"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TBSCertList, signature),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &AlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signature"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TBSCertList, issuer),
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &Name_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "issuer"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TBSCertList, thisUpdate),
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &PKIXTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "thisUpdate"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct TBSCertList, nextUpdate),
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &PKIXTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "nextUpdate"
    },
    {
        ATF_POINTER, 2, offsetof(struct TBSCertList, revokedCertificates),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &RevokedCertificates_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "revokedCertificates"
    },
    {
        ATF_POINTER, 1, offsetof(struct TBSCertList, crlExtensions),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &Extensions_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "crlExtensions"
    },
};
static const ber_tlv_tag_t TBSCertList_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_TBSCertList_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 2 }, /* signature */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, -1, 1 }, /* rdnSequence */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 5, -2, 0 }, /* revokedCertificates */
    { (ASN_TAG_CLASS_UNIVERSAL | (23 << 2)), 3, 0, 1 }, /* utcTime */
    { (ASN_TAG_CLASS_UNIVERSAL | (23 << 2)), 4, -1, 0 }, /* utcTime */
    { (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)), 3, 0, 1 }, /* generalTime */
    { (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)), 4, -1, 0 }, /* generalTime */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 6, 0, 0 } /* crlExtensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_TBSCertList_specs_1 = {
    sizeof(struct TBSCertList),
    offsetof(struct TBSCertList, _asn_ctx),
    asn_MAP_TBSCertList_tag2el_1,
    9,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t TBSCertList_desc = {
    "TBSCertList",
    "TBSCertList",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    TBSCertList_desc_tags_1,
    sizeof(TBSCertList_desc_tags_1)
    / sizeof(TBSCertList_desc_tags_1[0]), /* 1 */
    TBSCertList_desc_tags_1,    /* Same as above */
    sizeof(TBSCertList_desc_tags_1)
    / sizeof(TBSCertList_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_TBSCertList_1,
    7,    /* Elements count */
    &asn_SPC_TBSCertList_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_TBSCertList_desc(void)
{
    return &TBSCertList_desc;
}
