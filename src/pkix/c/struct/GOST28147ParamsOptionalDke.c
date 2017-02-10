/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "GOST28147ParamsOptionalDke.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/GOST28147ParamsOptionalDke.c"

static int
memb_iv_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
        asn_app_constraint_failed_f *ctfailcb, void *app_key)
{
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    size_t size;

    if (!sptr) {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: value not given (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }

    size = st->size;

    if (size == 8) {
        /* Constraint check succeeded */
        return 0;
    } else {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: constraint failed (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }
}

static int
memb_dke_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
        asn_app_constraint_failed_f *ctfailcb, void *app_key)
{
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    size_t size;

    if (!sptr) {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: value not given (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }

    size = st->size;

    if (size == 64) {
        /* Constraint check succeeded */
        return 0;
    } else {
        ASN__CTFAIL(app_key, td, sptr,
                "%s: constraint failed (%s:%d)",
                td->name, FILE_MARKER, __LINE__);
        return -1;
    }
}

static asn_TYPE_member_t asn_MBR_GOST28147ParamsOptionalDke_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct GOST28147ParamsOptionalDke, iv),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &OCTET_STRING_desc,
        memb_iv_constraint_1,
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "iv"
    },
    {
        ATF_POINTER, 1, offsetof(struct GOST28147ParamsOptionalDke, dke),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &OCTET_STRING_desc,
        memb_dke_constraint_1,
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "dke"
    },
};
static const ber_tlv_tag_t GOST28147ParamsOptionalDke_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_GOST28147ParamsOptionalDke_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, 0, 1 }, /* iv */
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 1, -1, 0 } /* dke */
};
static asn_SEQUENCE_specifics_t asn_SPC_GOST28147ParamsOptionalDke_specs_1 = {
    sizeof(struct GOST28147ParamsOptionalDke),
    offsetof(struct GOST28147ParamsOptionalDke, _asn_ctx),
    asn_MAP_GOST28147ParamsOptionalDke_tag2el_1,
    2,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t GOST28147ParamsOptionalDke_desc = {
    "GOST28147ParamsOptionalDke",
    "GOST28147ParamsOptionalDke",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    GOST28147ParamsOptionalDke_desc_tags_1,
    sizeof(GOST28147ParamsOptionalDke_desc_tags_1)
    / sizeof(GOST28147ParamsOptionalDke_desc_tags_1[0]), /* 1 */
    GOST28147ParamsOptionalDke_desc_tags_1,    /* Same as above */
    sizeof(GOST28147ParamsOptionalDke_desc_tags_1)
    / sizeof(GOST28147ParamsOptionalDke_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_GOST28147ParamsOptionalDke_1,
    2,    /* Elements count */
    &asn_SPC_GOST28147ParamsOptionalDke_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_GOST28147ParamsOptionalDke_desc(void)
{
    return &GOST28147ParamsOptionalDke_desc;
}
