/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "OriginatorPublicKey.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/OriginatorPublicKey.c"

static asn_TYPE_member_t asn_MBR_OriginatorPublicKey_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct OriginatorPublicKey, algorithm),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &AlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "algorithm"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct OriginatorPublicKey, publicKey),
        (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)),
        0,
        &BIT_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "publicKey"
    },
};
static const ber_tlv_tag_t OriginatorPublicKey_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_OriginatorPublicKey_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)), 1, 0, 0 }, /* publicKey */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 } /* algorithm */
};
static asn_SEQUENCE_specifics_t asn_SPC_OriginatorPublicKey_specs_1 = {
    sizeof(struct OriginatorPublicKey),
    offsetof(struct OriginatorPublicKey, _asn_ctx),
    asn_MAP_OriginatorPublicKey_tag2el_1,
    2,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t OriginatorPublicKey_desc = {
    "OriginatorPublicKey",
    "OriginatorPublicKey",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    OriginatorPublicKey_desc_tags_1,
    sizeof(OriginatorPublicKey_desc_tags_1)
    / sizeof(OriginatorPublicKey_desc_tags_1[0]), /* 1 */
    OriginatorPublicKey_desc_tags_1,    /* Same as above */
    sizeof(OriginatorPublicKey_desc_tags_1)
    / sizeof(OriginatorPublicKey_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_OriginatorPublicKey_1,
    2,    /* Elements count */
    &asn_SPC_OriginatorPublicKey_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_OriginatorPublicKey_desc(void)
{
    return &OriginatorPublicKey_desc;
}
