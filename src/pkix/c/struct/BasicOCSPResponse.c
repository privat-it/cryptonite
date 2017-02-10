/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "BasicOCSPResponse.h"

#include "asn_internal.h"

#include "Certificates.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/BasicOCSPResponse.c"

static asn_TYPE_member_t asn_MBR_BasicOCSPResponse_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct BasicOCSPResponse, tbsResponseData),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &ResponseData_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "tbsResponseData"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct BasicOCSPResponse, signatureAlgorithm),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &AlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signatureAlgorithm"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct BasicOCSPResponse, signature),
        (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)),
        0,
        &BIT_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signature"
    },
    {
        ATF_POINTER, 1, offsetof(struct BasicOCSPResponse, certs),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &Certificates_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "certs"
    },
};
static const ber_tlv_tag_t BasicOCSPResponse_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_BasicOCSPResponse_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)), 2, 0, 0 }, /* signature */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 1 }, /* tbsResponseData */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, -1, 0 }, /* signatureAlgorithm */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 3, 0, 0 } /* certs */
};
static asn_SEQUENCE_specifics_t asn_SPC_BasicOCSPResponse_specs_1 = {
    sizeof(struct BasicOCSPResponse),
    offsetof(struct BasicOCSPResponse, _asn_ctx),
    asn_MAP_BasicOCSPResponse_tag2el_1,
    4,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t BasicOCSPResponse_desc = {
    "BasicOCSPResponse",
    "BasicOCSPResponse",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    BasicOCSPResponse_desc_tags_1,
    sizeof(BasicOCSPResponse_desc_tags_1)
    / sizeof(BasicOCSPResponse_desc_tags_1[0]), /* 1 */
    BasicOCSPResponse_desc_tags_1,    /* Same as above */
    sizeof(BasicOCSPResponse_desc_tags_1)
    / sizeof(BasicOCSPResponse_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_BasicOCSPResponse_1,
    4,    /* Elements count */
    &asn_SPC_BasicOCSPResponse_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_BasicOCSPResponse_desc(void)
{
    return &BasicOCSPResponse_desc;
}
