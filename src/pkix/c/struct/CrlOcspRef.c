/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "CrlOcspRef.h"

#include "asn_internal.h"

#include "CRLListID.h"
#include "OcspListID.h"
#include "OtherRevRefs.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/CrlOcspRef.c"

static asn_TYPE_member_t asn_MBR_CrlOcspRef_1[] = {
    {
        ATF_POINTER, 3, offsetof(struct CrlOcspRef, crlids),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &CRLListID_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "crlids"
    },
    {
        ATF_POINTER, 2, offsetof(struct CrlOcspRef, ocspids),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &OcspListID_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "ocspids"
    },
    {
        ATF_POINTER, 1, offsetof(struct CrlOcspRef, otherRev),
        (ASN_TAG_CLASS_CONTEXT | (2 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &OtherRevRefs_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "otherRev"
    },
};
static const ber_tlv_tag_t CrlOcspRef_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CrlOcspRef_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* crlids */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* ocspids */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* otherRev */
};
static asn_SEQUENCE_specifics_t asn_SPC_CrlOcspRef_specs_1 = {
    sizeof(struct CrlOcspRef),
    offsetof(struct CrlOcspRef, _asn_ctx),
    asn_MAP_CrlOcspRef_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t CrlOcspRef_desc = {
    "CrlOcspRef",
    "CrlOcspRef",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    CrlOcspRef_desc_tags_1,
    sizeof(CrlOcspRef_desc_tags_1)
    / sizeof(CrlOcspRef_desc_tags_1[0]), /* 1 */
    CrlOcspRef_desc_tags_1,    /* Same as above */
    sizeof(CrlOcspRef_desc_tags_1)
    / sizeof(CrlOcspRef_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_CrlOcspRef_1,
    3,    /* Elements count */
    &asn_SPC_CrlOcspRef_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_CrlOcspRef_desc(void)
{
    return &CrlOcspRef_desc;
}
