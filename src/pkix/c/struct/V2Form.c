/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "V2Form.h"

#include "asn_internal.h"

#include "GeneralNames.h"
#include "IssuerSerial.h"
#include "ObjectDigestInfo.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/V2Form.c"

static asn_TYPE_member_t asn_MBR_V2Form_1[] = {
    {
        ATF_POINTER, 3, offsetof(struct V2Form, issuerName),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &GeneralNames_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "issuerName"
    },
    {
        ATF_POINTER, 2, offsetof(struct V2Form, baseCertificateID),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &IssuerSerial_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "baseCertificateID"
    },
    {
        ATF_POINTER, 1, offsetof(struct V2Form, objectDigestInfo),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &ObjectDigestInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "objectDigestInfo"
    },
};
static const ber_tlv_tag_t V2Form_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_V2Form_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 }, /* issuerName */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 }, /* baseCertificateID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 2, 0, 0 } /* objectDigestInfo */
};
static asn_SEQUENCE_specifics_t asn_SPC_V2Form_specs_1 = {
    sizeof(struct V2Form),
    offsetof(struct V2Form, _asn_ctx),
    asn_MAP_V2Form_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t V2Form_desc = {
    "V2Form",
    "V2Form",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    V2Form_desc_tags_1,
    sizeof(V2Form_desc_tags_1)
    / sizeof(V2Form_desc_tags_1[0]), /* 1 */
    V2Form_desc_tags_1,    /* Same as above */
    sizeof(V2Form_desc_tags_1)
    / sizeof(V2Form_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_V2Form_1,
    3,    /* Elements count */
    &asn_SPC_V2Form_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_V2Form_desc(void)
{
    return &V2Form_desc;
}
