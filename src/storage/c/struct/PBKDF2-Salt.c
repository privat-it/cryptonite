/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "PBKDF2-Salt.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/PBKDF2-Salt.c"

static asn_TYPE_member_t asn_MBR_PBKDF2_Salt_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct PBKDF2_Salt, choice.specified),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &OCTET_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "specified"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct PBKDF2_Salt, choice.otherSource),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &AlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "otherSource"
    },
};
static const asn_TYPE_tag2member_t asn_MAP_PBKDF2_Salt_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, 0, 0 }, /* specified */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 0 } /* otherSource */
};
static asn_CHOICE_specifics_t asn_SPC_PBKDF2_Salt_specs_1 = {
    sizeof(struct PBKDF2_Salt),
    offsetof(struct PBKDF2_Salt, _asn_ctx),
    offsetof(struct PBKDF2_Salt, present),
    sizeof(((struct PBKDF2_Salt *)0)->present),
    asn_MAP_PBKDF2_Salt_tag2el_1,
    2,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t PBKDF2_Salt_desc = {
    "PBKDF2-Salt",
    "PBKDF2-Salt",
    CHOICE_free,
    CHOICE_print,
    CHOICE_constraint,
    CHOICE_decode_ber,
    CHOICE_encode_der,
    CHOICE_decode_xer,
    CHOICE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    CHOICE_outmost_tag,
    0,    /* No effective tags (pointer) */
    0,    /* No effective tags (count) */
    0,    /* No tags (pointer) */
    0,    /* No tags (count) */
    0,    /* No PER visible constraints */
    asn_MBR_PBKDF2_Salt_1,
    2,    /* Elements count */
    &asn_SPC_PBKDF2_Salt_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_PBKDF2_Salt_desc(void)
{
    return &PBKDF2_Salt_desc;
}
