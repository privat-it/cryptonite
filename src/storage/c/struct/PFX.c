/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "PFX.h"

#include "asn_internal.h"

#include "MacData.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/PFX.c"

static int
memb_version_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
        asn_app_constraint_failed_f *ctfailcb, void *app_key)
{
    const INTEGER_t *st = (const INTEGER_t *)sptr;
    long value;

    if (!sptr) {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: value not given (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }

    if (asn_INTEGER2long(st, &value)) {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: value too large (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }

    if (value == 3) {
        /* Constraint check succeeded */
        return 0;
    } else {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: constraint failed (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }
}

static asn_TYPE_member_t asn_MBR_PFX_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct PFX, version),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        memb_version_constraint_1,
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "version"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct PFX, authSafe),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &ContentInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "authSafe"
    },
    {
        ATF_POINTER, 1, offsetof(struct PFX, macData),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &MacData_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "macData"
    },
};
static const ber_tlv_tag_t PFX_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PFX_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 1 }, /* authSafe */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, -1, 0 } /* macData */
};
static asn_SEQUENCE_specifics_t asn_SPC_PFX_specs_1 = {
    sizeof(struct PFX),
    offsetof(struct PFX, _asn_ctx),
    asn_MAP_PFX_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t PFX_desc = {
    "PFX",
    "PFX",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    PFX_desc_tags_1,
    sizeof(PFX_desc_tags_1)
    / sizeof(PFX_desc_tags_1[0]), /* 1 */
    PFX_desc_tags_1,    /* Same as above */
    sizeof(PFX_desc_tags_1)
    / sizeof(PFX_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_PFX_1,
    3,    /* Elements count */
    &asn_SPC_PFX_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_PFX_desc(void)
{
    return &PFX_desc;
}
