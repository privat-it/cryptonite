/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "ECPrivateKey.h"

#include "asn_internal.h"

#include "ECParameters.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/ECPrivateKey.c"

static asn_TYPE_member_t asn_MBR_ECPrivateKey_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct ECPrivateKey, version),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &Version_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "version"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct ECPrivateKey, privateKey),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &OCTET_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "privateKey"
    },
    {
        ATF_POINTER, 2, offsetof(struct ECPrivateKey, parameters),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &ECParameters_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "parameters"
    },
    {
        ATF_POINTER, 1, offsetof(struct ECPrivateKey, publicKey),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &BIT_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "publicKey"
    },
};
static const ber_tlv_tag_t ECPrivateKey_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ECPrivateKey_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 1, 0, 0 }, /* privateKey */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 2, 0, 0 }, /* parameters */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 3, 0, 0 } /* publicKey */
};
static asn_SEQUENCE_specifics_t asn_SPC_ECPrivateKey_specs_1 = {
    sizeof(struct ECPrivateKey),
    offsetof(struct ECPrivateKey, _asn_ctx),
    asn_MAP_ECPrivateKey_tag2el_1,
    4,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t ECPrivateKey_desc = {
    "ECPrivateKey",
    "ECPrivateKey",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    ECPrivateKey_desc_tags_1,
    sizeof(ECPrivateKey_desc_tags_1)
    / sizeof(ECPrivateKey_desc_tags_1[0]), /* 1 */
    ECPrivateKey_desc_tags_1,    /* Same as above */
    sizeof(ECPrivateKey_desc_tags_1)
    / sizeof(ECPrivateKey_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_ECPrivateKey_1,
    4,    /* Elements count */
    &asn_SPC_ECPrivateKey_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_ECPrivateKey_desc(void)
{
    return &ECPrivateKey_desc;
}
