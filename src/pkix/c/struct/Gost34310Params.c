/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "Gost34310Params.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/Gost34310Params.c"

static asn_TYPE_member_t asn_MBR_sequence_2[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct sequence, p),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "p"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct sequence, q),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "q"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct sequence, a),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "a"
    },
};
static const ber_tlv_tag_t sequence_desc_tags_2[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_sequence_tag2el_2[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 2 }, /* p */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 1, -1, 1 }, /* q */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 2, -2, 0 } /* a */
};
static asn_SEQUENCE_specifics_t asn_SPC_sequence_specs_2 = {
    sizeof(struct sequence),
    offsetof(struct sequence, _asn_ctx),
    asn_MAP_sequence_tag2el_2,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t sequence_2_desc = {
    "sequence",
    "sequence",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    sequence_desc_tags_2,
    sizeof(sequence_desc_tags_2)
    / sizeof(sequence_desc_tags_2[0]), /* 1 */
    sequence_desc_tags_2,    /* Same as above */
    sizeof(sequence_desc_tags_2)
    / sizeof(sequence_desc_tags_2[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_sequence_2,
    3,    /* Elements count */
    &asn_SPC_sequence_specs_2    /* Additional specs */
};

static asn_TYPE_member_t asn_MBR_Gost34310Params_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct Gost34310Params, sequence),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &sequence_2_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "sequence"
    },
    {
        ATF_POINTER, 1, offsetof(struct Gost34310Params, dke),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &OCTET_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "dke"
    },
};
static const ber_tlv_tag_t Gost34310Params_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Gost34310Params_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 1, 0, 0 }, /* dke */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 } /* sequence */
};
static asn_SEQUENCE_specifics_t asn_SPC_Gost34310Params_specs_1 = {
    sizeof(struct Gost34310Params),
    offsetof(struct Gost34310Params, _asn_ctx),
    asn_MAP_Gost34310Params_tag2el_1,
    2,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t Gost34310Params_desc = {
    "Gost34310Params",
    "Gost34310Params",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    Gost34310Params_desc_tags_1,
    sizeof(Gost34310Params_desc_tags_1)
    / sizeof(Gost34310Params_desc_tags_1[0]), /* 1 */
    Gost34310Params_desc_tags_1,    /* Same as above */
    sizeof(Gost34310Params_desc_tags_1)
    / sizeof(Gost34310Params_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_Gost34310Params_1,
    2,    /* Elements count */
    &asn_SPC_Gost34310Params_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_Gost34310Params_desc(void)
{
    return &Gost34310Params_desc;
}
