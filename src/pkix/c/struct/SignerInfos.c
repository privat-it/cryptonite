/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "SignerInfos.h"

#include "asn_internal.h"

#include "SignerInfo.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/SignerInfos.c"

static asn_TYPE_member_t asn_MBR_SignerInfos_1[] = {
    {
        ATF_POINTER, 0, 0,
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &SignerInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        ""
    },
};
static const ber_tlv_tag_t SignerInfos_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (17 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_SignerInfos_specs_1 = {
    sizeof(struct SignerInfos),
    offsetof(struct SignerInfos, _asn_ctx),
    0,    /* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t SignerInfos_desc = {
    "SignerInfos",
    "SignerInfos",
    SET_OF_free,
    SET_OF_print,
    SET_OF_constraint,
    SET_OF_decode_ber,
    SET_OF_encode_der,
    SET_OF_decode_xer,
    SET_OF_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    SignerInfos_desc_tags_1,
    sizeof(SignerInfos_desc_tags_1)
    / sizeof(SignerInfos_desc_tags_1[0]), /* 1 */
    SignerInfos_desc_tags_1,    /* Same as above */
    sizeof(SignerInfos_desc_tags_1)
    / sizeof(SignerInfos_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_SignerInfos_1,
    1,    /* Single element */
    &asn_SPC_SignerInfos_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_SignerInfos_desc(void)
{
    return &SignerInfos_desc;
}
