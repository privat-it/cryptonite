/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "CRLDistributionPoints.h"

#include "asn_internal.h"

#include "DistributionPoint.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/CRLDistributionPoints.c"

static asn_TYPE_member_t asn_MBR_CRLDistributionPoints_1[] = {
    {
        ATF_POINTER, 0, 0,
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &DistributionPoint_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        ""
    },
};
static const ber_tlv_tag_t CRLDistributionPoints_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_CRLDistributionPoints_specs_1 = {
    sizeof(struct CRLDistributionPoints),
    offsetof(struct CRLDistributionPoints, _asn_ctx),
    0,    /* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t CRLDistributionPoints_desc = {
    "CRLDistributionPoints",
    "CRLDistributionPoints",
    SEQUENCE_OF_free,
    SEQUENCE_OF_print,
    SEQUENCE_OF_constraint,
    SEQUENCE_OF_decode_ber,
    SEQUENCE_OF_encode_der,
    SEQUENCE_OF_decode_xer,
    SEQUENCE_OF_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    CRLDistributionPoints_desc_tags_1,
    sizeof(CRLDistributionPoints_desc_tags_1)
    / sizeof(CRLDistributionPoints_desc_tags_1[0]), /* 1 */
    CRLDistributionPoints_desc_tags_1,    /* Same as above */
    sizeof(CRLDistributionPoints_desc_tags_1)
    / sizeof(CRLDistributionPoints_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_CRLDistributionPoints_1,
    1,    /* Single element */
    &asn_SPC_CRLDistributionPoints_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_CRLDistributionPoints_desc(void)
{
    return &CRLDistributionPoints_desc;
}
