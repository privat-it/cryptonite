/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "DSTU4145Params.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/DSTU4145Params.c"

static asn_TYPE_member_t asn_MBR_DSTU4145Params_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct DSTU4145Params, ellipticCurve),
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &DSTUEllipticCurve_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "ellipticCurve"
    },
    {
        ATF_POINTER, 1, offsetof(struct DSTU4145Params, dke),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &OCTET_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "dke"
    },
};
static const ber_tlv_tag_t DSTU4145Params_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DSTU4145Params_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 1, 0, 0 }, /* dke */
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 0, 0, 0 }, /* namedCurve */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 } /* ecbinary */
};
static asn_SEQUENCE_specifics_t asn_SPC_DSTU4145Params_specs_1 = {
    sizeof(struct DSTU4145Params),
    offsetof(struct DSTU4145Params, _asn_ctx),
    asn_MAP_DSTU4145Params_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t DSTU4145Params_desc = {
    "DSTU4145Params",
    "DSTU4145Params",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    DSTU4145Params_desc_tags_1,
    sizeof(DSTU4145Params_desc_tags_1)
    / sizeof(DSTU4145Params_desc_tags_1[0]), /* 1 */
    DSTU4145Params_desc_tags_1,    /* Same as above */
    sizeof(DSTU4145Params_desc_tags_1)
    / sizeof(DSTU4145Params_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_DSTU4145Params_1,
    2,    /* Elements count */
    &asn_SPC_DSTU4145Params_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_DSTU4145Params_desc(void)
{
    return &DSTU4145Params_desc;
}
