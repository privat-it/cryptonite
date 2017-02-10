/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "PrivateDomainName.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/PrivateDomainName.c"

static asn_TYPE_member_t asn_MBR_PrivateDomainName_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct PrivateDomainName, choice.numeric),
        (ASN_TAG_CLASS_UNIVERSAL | (18 << 2)),
        0,
        &NumericString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "numeric"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct PrivateDomainName, choice.printable),
        (ASN_TAG_CLASS_UNIVERSAL | (19 << 2)),
        0,
        &PrintableString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "printable"
    },
};
static const asn_TYPE_tag2member_t asn_MAP_PrivateDomainName_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (18 << 2)), 0, 0, 0 }, /* numeric */
    { (ASN_TAG_CLASS_UNIVERSAL | (19 << 2)), 1, 0, 0 } /* printable */
};
static asn_CHOICE_specifics_t asn_SPC_PrivateDomainName_specs_1 = {
    sizeof(struct PrivateDomainName),
    offsetof(struct PrivateDomainName, _asn_ctx),
    offsetof(struct PrivateDomainName, present),
    sizeof(((struct PrivateDomainName *)0)->present),
    asn_MAP_PrivateDomainName_tag2el_1,
    2,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t PrivateDomainName_desc = {
    "PrivateDomainName",
    "PrivateDomainName",
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
    asn_MBR_PrivateDomainName_1,
    2,    /* Elements count */
    &asn_SPC_PrivateDomainName_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_PrivateDomainName_desc(void)
{
    return &PrivateDomainName_desc;
}
