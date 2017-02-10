/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "CertStatus.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/CertStatus.c"

static asn_TYPE_member_t asn_MBR_CertStatus_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct CertStatus, choice.good),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &NULL_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "good"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CertStatus, choice.revoked),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &RevokedInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "revoked"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CertStatus, choice.unknown),
        (ASN_TAG_CLASS_CONTEXT | (2 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &UnknownInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "unknown"
    },
};
static const asn_TYPE_tag2member_t asn_MAP_CertStatus_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* good */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* revoked */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* unknown */
};
static asn_CHOICE_specifics_t asn_SPC_CertStatus_specs_1 = {
    sizeof(struct CertStatus),
    offsetof(struct CertStatus, _asn_ctx),
    offsetof(struct CertStatus, present),
    sizeof(((struct CertStatus *)0)->present),
    asn_MAP_CertStatus_tag2el_1,
    3,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t CertStatus_desc = {
    "CertStatus",
    "CertStatus",
    CHOICE_free,
    CHOICE_print,
    CHOICE_constraint,
    CHOICE_decode_ber,
    CHOICE_encode_der,
    CHOICE_decode_xer,
    CHOICE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    CHOICE_outmost_tag,
    0,    /* No effective tags (pointer) */
    0,    /* No effective tags (count) */
    0,    /* No tags (pointer) */
    0,    /* No tags (count) */
    0,    /* No PER visible constraints */
    asn_MBR_CertStatus_1,
    3,    /* Elements count */
    &asn_SPC_CertStatus_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_CertStatus_desc(void)
{
    return &CertStatus_desc;
}
