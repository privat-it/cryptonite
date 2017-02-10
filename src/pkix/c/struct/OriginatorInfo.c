/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "OriginatorInfo.h"

#include "asn_internal.h"

#include "CertificateSet.h"
#include "RevocationInfoChoices.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/OriginatorInfo.c"

static asn_TYPE_member_t asn_MBR_OriginatorInfo_1[] = {
    {
        ATF_POINTER, 2, offsetof(struct OriginatorInfo, certs),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &CertificateSet_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "certs"
    },
    {
        ATF_POINTER, 1, offsetof(struct OriginatorInfo, crls),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &RevocationInfoChoices_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "crls"
    },
};
static const ber_tlv_tag_t OriginatorInfo_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_OriginatorInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* certs */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* crls */
};
static asn_SEQUENCE_specifics_t asn_SPC_OriginatorInfo_specs_1 = {
    sizeof(struct OriginatorInfo),
    offsetof(struct OriginatorInfo, _asn_ctx),
    asn_MAP_OriginatorInfo_tag2el_1,
    2,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t OriginatorInfo_desc = {
    "OriginatorInfo",
    "OriginatorInfo",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    OriginatorInfo_desc_tags_1,
    sizeof(OriginatorInfo_desc_tags_1)
    / sizeof(OriginatorInfo_desc_tags_1[0]), /* 1 */
    OriginatorInfo_desc_tags_1,    /* Same as above */
    sizeof(OriginatorInfo_desc_tags_1)
    / sizeof(OriginatorInfo_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_OriginatorInfo_1,
    2,    /* Elements count */
    &asn_SPC_OriginatorInfo_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_OriginatorInfo_desc(void)
{
    return &OriginatorInfo_desc;
}
