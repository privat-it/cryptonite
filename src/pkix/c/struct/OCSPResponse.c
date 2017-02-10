/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "OCSPResponse.h"

#include "asn_internal.h"

#include "ResponseBytes.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/OCSPResponse.c"

static asn_TYPE_member_t asn_MBR_OCSPResponse_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct OCSPResponse, responseStatus),
        (ASN_TAG_CLASS_UNIVERSAL | (10 << 2)),
        0,
        &OCSPResponseStatus_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "responseStatus"
    },
    {
        ATF_POINTER, 1, offsetof(struct OCSPResponse, responseBytes),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &ResponseBytes_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "responseBytes"
    },
};
static const ber_tlv_tag_t OCSPResponse_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_OCSPResponse_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (10 << 2)), 0, 0, 0 }, /* responseStatus */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 } /* responseBytes */
};
static asn_SEQUENCE_specifics_t asn_SPC_OCSPResponse_specs_1 = {
    sizeof(struct OCSPResponse),
    offsetof(struct OCSPResponse, _asn_ctx),
    asn_MAP_OCSPResponse_tag2el_1,
    2,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t OCSPResponse_desc = {
    "OCSPResponse",
    "OCSPResponse",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    OCSPResponse_desc_tags_1,
    sizeof(OCSPResponse_desc_tags_1)
    / sizeof(OCSPResponse_desc_tags_1[0]), /* 1 */
    OCSPResponse_desc_tags_1,    /* Same as above */
    sizeof(OCSPResponse_desc_tags_1)
    / sizeof(OCSPResponse_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_OCSPResponse_1,
    2,    /* Elements count */
    &asn_SPC_OCSPResponse_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_OCSPResponse_desc(void)
{
    return &OCSPResponse_desc;
}
