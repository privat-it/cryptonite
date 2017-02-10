/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "OCSPRequest.h"

#include "asn_internal.h"

#include "Signature.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/OCSPRequest.c"

static asn_TYPE_member_t asn_MBR_OCSPRequest_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct OCSPRequest, tbsRequest),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &TBSRequest_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "tbsRequest"
    },
    {
        ATF_POINTER, 1, offsetof(struct OCSPRequest, optionalSignature),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &Signature_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "optionalSignature"
    },
};
static const ber_tlv_tag_t OCSPRequest_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_OCSPRequest_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 }, /* tbsRequest */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 } /* optionalSignature */
};
static asn_SEQUENCE_specifics_t asn_SPC_OCSPRequest_specs_1 = {
    sizeof(struct OCSPRequest),
    offsetof(struct OCSPRequest, _asn_ctx),
    asn_MAP_OCSPRequest_tag2el_1,
    2,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t OCSPRequest_desc = {
    "OCSPRequest",
    "OCSPRequest",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    OCSPRequest_desc_tags_1,
    sizeof(OCSPRequest_desc_tags_1)
    / sizeof(OCSPRequest_desc_tags_1[0]), /* 1 */
    OCSPRequest_desc_tags_1,    /* Same as above */
    sizeof(OCSPRequest_desc_tags_1)
    / sizeof(OCSPRequest_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_OCSPRequest_1,
    2,    /* Elements count */
    &asn_SPC_OCSPRequest_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_OCSPRequest_desc(void)
{
    return &OCSPRequest_desc;
}
