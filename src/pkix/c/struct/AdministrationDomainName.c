/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "AdministrationDomainName.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/AdministrationDomainName.c"

static asn_TYPE_member_t asn_MBR_AdministrationDomainName_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct AdministrationDomainName, choice.numeric),
        (ASN_TAG_CLASS_UNIVERSAL | (18 << 2)),
        0,
        &NumericString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "numeric"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct AdministrationDomainName, choice.printable),
        (ASN_TAG_CLASS_UNIVERSAL | (19 << 2)),
        0,
        &PrintableString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "printable"
    },
};
static const ber_tlv_tag_t AdministrationDomainName_desc_tags_1[] = {
    (ASN_TAG_CLASS_APPLICATION | (2 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_AdministrationDomainName_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (18 << 2)), 0, 0, 0 }, /* numeric */
    { (ASN_TAG_CLASS_UNIVERSAL | (19 << 2)), 1, 0, 0 } /* printable */
};
static asn_CHOICE_specifics_t asn_SPC_AdministrationDomainName_specs_1 = {
    sizeof(struct AdministrationDomainName),
    offsetof(struct AdministrationDomainName, _asn_ctx),
    offsetof(struct AdministrationDomainName, present),
    sizeof(((struct AdministrationDomainName *)0)->present),
    asn_MAP_AdministrationDomainName_tag2el_1,
    2,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t AdministrationDomainName_desc = {
    "AdministrationDomainName",
    "AdministrationDomainName",
    CHOICE_free,
    CHOICE_print,
    CHOICE_constraint,
    CHOICE_decode_ber,
    CHOICE_encode_der,
    CHOICE_decode_xer,
    CHOICE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    CHOICE_outmost_tag,
    AdministrationDomainName_desc_tags_1,
    sizeof(AdministrationDomainName_desc_tags_1)
    / sizeof(AdministrationDomainName_desc_tags_1[0]), /* 1 */
    AdministrationDomainName_desc_tags_1,    /* Same as above */
    sizeof(AdministrationDomainName_desc_tags_1)
    / sizeof(AdministrationDomainName_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_AdministrationDomainName_1,
    2,    /* Elements count */
    &asn_SPC_AdministrationDomainName_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_AdministrationDomainName_desc(void)
{
    return &AdministrationDomainName_desc;
}
