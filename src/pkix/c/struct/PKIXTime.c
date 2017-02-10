/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "PKIXTime.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/PKIXTime.c"

static asn_TYPE_member_t asn_MBR_PKIXTime_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct PKIXTime, choice.utcTime),
        (ASN_TAG_CLASS_UNIVERSAL | (23 << 2)),
        0,
        &UTCTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "utcTime"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct PKIXTime, choice.generalTime),
        (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)),
        0,
        &GeneralizedTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "generalTime"
    },
};
static const asn_TYPE_tag2member_t asn_MAP_PKIXTime_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (23 << 2)), 0, 0, 0 }, /* utcTime */
    { (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)), 1, 0, 0 } /* generalTime */
};
static asn_CHOICE_specifics_t asn_SPC_PKIXTime_specs_1 = {
    sizeof(struct PKIXTime),
    offsetof(struct PKIXTime, _asn_ctx),
    offsetof(struct PKIXTime, present),
    sizeof(((struct PKIXTime *)0)->present),
    asn_MAP_PKIXTime_tag2el_1,
    2,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t PKIXTime_desc = {
    "PKIXTime",
    "PKIXTime",
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
    asn_MBR_PKIXTime_1,
    2,    /* Elements count */
    &asn_SPC_PKIXTime_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_PKIXTime_desc(void)
{
    return &PKIXTime_desc;
}
