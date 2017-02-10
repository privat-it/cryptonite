/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "Signature.h"

#include "asn_internal.h"

#include "Certificates.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/Signature.c"

static asn_TYPE_member_t asn_MBR_Signature_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct Signature, signatureAlgorithm),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &AlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signatureAlgorithm"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct Signature, signature),
        (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)),
        0,
        &BIT_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signature"
    },
    {
        ATF_POINTER, 1, offsetof(struct Signature, certs),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &Certificates_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "certs"
    },
};
static const ber_tlv_tag_t Signature_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Signature_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)), 1, 0, 0 }, /* signature */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 }, /* signatureAlgorithm */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 2, 0, 0 } /* certs */
};
static asn_SEQUENCE_specifics_t asn_SPC_Signature_specs_1 = {
    sizeof(struct Signature),
    offsetof(struct Signature, _asn_ctx),
    asn_MAP_Signature_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t Signature_desc = {
    "Signature",
    "Signature",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    Signature_desc_tags_1,
    sizeof(Signature_desc_tags_1)
    / sizeof(Signature_desc_tags_1[0]), /* 1 */
    Signature_desc_tags_1,    /* Same as above */
    sizeof(Signature_desc_tags_1)
    / sizeof(Signature_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_Signature_1,
    3,    /* Elements count */
    &asn_SPC_Signature_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_Signature_desc(void)
{
    return &Signature_desc;
}
