/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "TimeStampResp.h"

#include "asn_internal.h"

#include "TimeStampToken.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/TimeStampResp.c"

static asn_TYPE_member_t asn_MBR_TimeStampResp_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct TimeStampResp, status),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &PKIStatusInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "status"
    },
    {
        ATF_POINTER, 1, offsetof(struct TimeStampResp, timeStampToken),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &TimeStampToken_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "timeStampToken"
    },
};
static const ber_tlv_tag_t TimeStampResp_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_TimeStampResp_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 1 }, /* status */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, -1, 0 } /* timeStampToken */
};
static asn_SEQUENCE_specifics_t asn_SPC_TimeStampResp_specs_1 = {
    sizeof(struct TimeStampResp),
    offsetof(struct TimeStampResp, _asn_ctx),
    asn_MAP_TimeStampResp_tag2el_1,
    2,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t TimeStampResp_desc = {
    "TimeStampResp",
    "TimeStampResp",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    TimeStampResp_desc_tags_1,
    sizeof(TimeStampResp_desc_tags_1)
    / sizeof(TimeStampResp_desc_tags_1[0]), /* 1 */
    TimeStampResp_desc_tags_1,    /* Same as above */
    sizeof(TimeStampResp_desc_tags_1)
    / sizeof(TimeStampResp_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_TimeStampResp_1,
    2,    /* Elements count */
    &asn_SPC_TimeStampResp_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_TimeStampResp_desc(void)
{
    return &TimeStampResp_desc;
}
