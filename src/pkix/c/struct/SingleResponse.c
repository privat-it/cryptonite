/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "SingleResponse.h"

#include "asn_internal.h"

#include "Extensions.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/SingleResponse.c"

static asn_TYPE_member_t asn_MBR_SingleResponse_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct SingleResponse, certID),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &CertID_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "certID"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct SingleResponse, certStatus),
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &CertStatus_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "certStatus"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct SingleResponse, thisUpdate),
        (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)),
        0,
        &GeneralizedTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "thisUpdate"
    },
    {
        ATF_POINTER, 2, offsetof(struct SingleResponse, nextUpdate),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &GeneralizedTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "nextUpdate"
    },
    {
        ATF_POINTER, 1, offsetof(struct SingleResponse, singleExtensions),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &Extensions_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "singleExtensions"
    },
};
static const ber_tlv_tag_t SingleResponse_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SingleResponse_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 }, /* certID */
    { (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)), 2, 0, 0 }, /* thisUpdate */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 1 }, /* good */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 3, -1, 0 }, /* nextUpdate */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 1 }, /* revoked */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 4, -1, 0 }, /* singleExtensions */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 1, 0, 0 } /* unknown */
};
static asn_SEQUENCE_specifics_t asn_SPC_SingleResponse_specs_1 = {
    sizeof(struct SingleResponse),
    offsetof(struct SingleResponse, _asn_ctx),
    asn_MAP_SingleResponse_tag2el_1,
    7,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t SingleResponse_desc = {
    "SingleResponse",
    "SingleResponse",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    SingleResponse_desc_tags_1,
    sizeof(SingleResponse_desc_tags_1)
    / sizeof(SingleResponse_desc_tags_1[0]), /* 1 */
    SingleResponse_desc_tags_1,    /* Same as above */
    sizeof(SingleResponse_desc_tags_1)
    / sizeof(SingleResponse_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_SingleResponse_1,
    5,    /* Elements count */
    &asn_SPC_SingleResponse_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_SingleResponse_desc(void)
{
    return &SingleResponse_desc;
}
