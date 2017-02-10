/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "RecipientInfos.h"

#include "asn_internal.h"

#include "RecipientInfo.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/RecipientInfos.c"

static asn_TYPE_member_t asn_MBR_RecipientInfos_1[] = {
    {
        ATF_POINTER, 0, 0,
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &RecipientInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        ""
    },
};
static const ber_tlv_tag_t RecipientInfos_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (17 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_RecipientInfos_specs_1 = {
    sizeof(struct RecipientInfos),
    offsetof(struct RecipientInfos, _asn_ctx),
    2,    /* XER encoding is XMLValueList */
};
asn_TYPE_descriptor_t RecipientInfos_desc = {
    "RecipientInfos",
    "RecipientInfos",
    SET_OF_free,
    SET_OF_print,
    SET_OF_constraint,
    SET_OF_decode_ber,
    SET_OF_encode_der,
    SET_OF_decode_xer,
    SET_OF_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    RecipientInfos_desc_tags_1,
    sizeof(RecipientInfos_desc_tags_1)
    / sizeof(RecipientInfos_desc_tags_1[0]), /* 1 */
    RecipientInfos_desc_tags_1,    /* Same as above */
    sizeof(RecipientInfos_desc_tags_1)
    / sizeof(RecipientInfos_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_RecipientInfos_1,
    1,    /* Single element */
    &asn_SPC_RecipientInfos_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_RecipientInfos_desc(void)
{
    return &RecipientInfos_desc;
}
