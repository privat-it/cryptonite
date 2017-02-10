/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "RevokedCertificates.h"

#include "asn_internal.h"

#include "RevokedCertificate.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/RevokedCertificates.c"

static asn_TYPE_member_t asn_MBR_RevokedCertificates_1[] = {
    {
        ATF_POINTER, 0, 0,
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &RevokedCertificate_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        ""
    },
};
static const ber_tlv_tag_t RevokedCertificates_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_RevokedCertificates_specs_1 = {
    sizeof(struct RevokedCertificates),
    offsetof(struct RevokedCertificates, _asn_ctx),
    0,    /* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t RevokedCertificates_desc = {
    "RevokedCertificates",
    "RevokedCertificates",
    SEQUENCE_OF_free,
    SEQUENCE_OF_print,
    SEQUENCE_OF_constraint,
    SEQUENCE_OF_decode_ber,
    SEQUENCE_OF_encode_der,
    SEQUENCE_OF_decode_xer,
    SEQUENCE_OF_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    RevokedCertificates_desc_tags_1,
    sizeof(RevokedCertificates_desc_tags_1)
    / sizeof(RevokedCertificates_desc_tags_1[0]), /* 1 */
    RevokedCertificates_desc_tags_1,    /* Same as above */
    sizeof(RevokedCertificates_desc_tags_1)
    / sizeof(RevokedCertificates_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_RevokedCertificates_1,
    1,    /* Single element */
    &asn_SPC_RevokedCertificates_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_RevokedCertificates_desc(void)
{
    return &RevokedCertificates_desc;
}
