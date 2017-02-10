/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "RevokedCertificate.h"

#include "asn_internal.h"

#include "Extensions.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/RevokedCertificate.c"

static asn_TYPE_member_t asn_MBR_RevokedCertificate_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct RevokedCertificate, userCertificate),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &CertificateSerialNumber_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "userCertificate"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct RevokedCertificate, revocationDate),
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &PKIXTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "revocationDate"
    },
    {
        ATF_POINTER, 1, offsetof(struct RevokedCertificate, crlEntryExtensions),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &Extensions_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "crlEntryExtensions"
    },
};
static const ber_tlv_tag_t RevokedCertificate_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RevokedCertificate_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }, /* userCertificate */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, 0, 0 }, /* crlEntryExtensions */
    { (ASN_TAG_CLASS_UNIVERSAL | (23 << 2)), 1, 0, 0 }, /* utcTime */
    { (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)), 1, 0, 0 } /* generalTime */
};
static asn_SEQUENCE_specifics_t asn_SPC_RevokedCertificate_specs_1 = {
    sizeof(struct RevokedCertificate),
    offsetof(struct RevokedCertificate, _asn_ctx),
    asn_MAP_RevokedCertificate_tag2el_1,
    4,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t RevokedCertificate_desc = {
    "RevokedCertificate",
    "RevokedCertificate",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    RevokedCertificate_desc_tags_1,
    sizeof(RevokedCertificate_desc_tags_1)
    / sizeof(RevokedCertificate_desc_tags_1[0]), /* 1 */
    RevokedCertificate_desc_tags_1,    /* Same as above */
    sizeof(RevokedCertificate_desc_tags_1)
    / sizeof(RevokedCertificate_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_RevokedCertificate_1,
    3,    /* Elements count */
    &asn_SPC_RevokedCertificate_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_RevokedCertificate_desc(void)
{
    return &RevokedCertificate_desc;
}
