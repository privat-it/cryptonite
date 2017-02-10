/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "RecipientEncryptedKey.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/RecipientEncryptedKey.c"

static asn_TYPE_member_t asn_MBR_RecipientEncryptedKey_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct RecipientEncryptedKey, rid),
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &KeyAgreeRecipientIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "rid"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct RecipientEncryptedKey, encryptedKey),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &EncryptedKey_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "encryptedKey"
    },
};
static const ber_tlv_tag_t RecipientEncryptedKey_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RecipientEncryptedKey_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 1, 0, 0 }, /* encryptedKey */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 }, /* issuerAndSerialNumber */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* rKeyId */
};
static asn_SEQUENCE_specifics_t asn_SPC_RecipientEncryptedKey_specs_1 = {
    sizeof(struct RecipientEncryptedKey),
    offsetof(struct RecipientEncryptedKey, _asn_ctx),
    asn_MAP_RecipientEncryptedKey_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t RecipientEncryptedKey_desc = {
    "RecipientEncryptedKey",
    "RecipientEncryptedKey",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    RecipientEncryptedKey_desc_tags_1,
    sizeof(RecipientEncryptedKey_desc_tags_1)
    / sizeof(RecipientEncryptedKey_desc_tags_1[0]), /* 1 */
    RecipientEncryptedKey_desc_tags_1,    /* Same as above */
    sizeof(RecipientEncryptedKey_desc_tags_1)
    / sizeof(RecipientEncryptedKey_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_RecipientEncryptedKey_1,
    2,    /* Elements count */
    &asn_SPC_RecipientEncryptedKey_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_RecipientEncryptedKey_desc(void)
{
    return &RecipientEncryptedKey_desc;
}
