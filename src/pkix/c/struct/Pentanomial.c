/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "Pentanomial.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/Pentanomial.c"

static asn_TYPE_member_t asn_MBR_Pentanomial_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct Pentanomial, k),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "k"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct Pentanomial, j),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "j"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct Pentanomial, l),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "l"
    },
};
static const ber_tlv_tag_t Pentanomial_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Pentanomial_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 2 }, /* k */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 1, -1, 1 }, /* j */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 2, -2, 0 } /* l */
};
static asn_SEQUENCE_specifics_t asn_SPC_Pentanomial_specs_1 = {
    sizeof(struct Pentanomial),
    offsetof(struct Pentanomial, _asn_ctx),
    asn_MAP_Pentanomial_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t Pentanomial_desc = {
    "Pentanomial",
    "Pentanomial",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    Pentanomial_desc_tags_1,
    sizeof(Pentanomial_desc_tags_1)
    / sizeof(Pentanomial_desc_tags_1[0]), /* 1 */
    Pentanomial_desc_tags_1,    /* Same as above */
    sizeof(Pentanomial_desc_tags_1)
    / sizeof(Pentanomial_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_Pentanomial_1,
    3,    /* Elements count */
    &asn_SPC_Pentanomial_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_Pentanomial_desc(void)
{
    return &Pentanomial_desc;
}
