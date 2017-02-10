/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "EncryptedPrivateKeyInfo.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/EncryptedPrivateKeyInfo.c"

static asn_TYPE_member_t asn_MBR_EncryptedPrivateKeyInfo_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct EncryptedPrivateKeyInfo, encryptionAlgorithm),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &AlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "encryptionAlgorithm"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct EncryptedPrivateKeyInfo, encryptedData),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &OCTET_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "encryptedData"
    },
};
static const ber_tlv_tag_t EncryptedPrivateKeyInfo_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_EncryptedPrivateKeyInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 1, 0, 0 }, /* encryptedData */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 } /* encryptionAlgorithm */
};
static asn_SEQUENCE_specifics_t asn_SPC_EncryptedPrivateKeyInfo_specs_1 = {
    sizeof(struct EncryptedPrivateKeyInfo),
    offsetof(struct EncryptedPrivateKeyInfo, _asn_ctx),
    asn_MAP_EncryptedPrivateKeyInfo_tag2el_1,
    2,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t EncryptedPrivateKeyInfo_desc = {
    "EncryptedPrivateKeyInfo",
    "EncryptedPrivateKeyInfo",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    EncryptedPrivateKeyInfo_desc_tags_1,
    sizeof(EncryptedPrivateKeyInfo_desc_tags_1)
    / sizeof(EncryptedPrivateKeyInfo_desc_tags_1[0]), /* 1 */
    EncryptedPrivateKeyInfo_desc_tags_1,    /* Same as above */
    sizeof(EncryptedPrivateKeyInfo_desc_tags_1)
    / sizeof(EncryptedPrivateKeyInfo_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_EncryptedPrivateKeyInfo_1,
    2,    /* Elements count */
    &asn_SPC_EncryptedPrivateKeyInfo_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_EncryptedPrivateKeyInfo_desc(void)
{
    return &EncryptedPrivateKeyInfo_desc;
}
