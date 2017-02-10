/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "asn_internal.h"
#include "GeneralString.h"

#undef FILE_MARKER
#define FILE_MARKER "asn1/GeneralString.c"

/*
 * GeneralString basic type description.
 */
static const ber_tlv_tag_t asn_DEF_GeneralString_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (27 << 2)),    /* [UNIVERSAL 27] IMPLICIT ...*/
    (ASN_TAG_CLASS_UNIVERSAL | (4 << 2))    /* ... OCTET STRING */
};
asn_TYPE_descriptor_t GeneralString_desc = {
    "GeneralString",
    "GeneralString",
    OCTET_STRING_free,
    OCTET_STRING_print,         /* non-ascii string */
    asn_generic_unknown_constraint,
    OCTET_STRING_decode_ber,    /* Implemented in terms of OCTET STRING */
    OCTET_STRING_encode_der,
    OCTET_STRING_decode_xer_hex,
    OCTET_STRING_encode_xer,
    OCTET_STRING_decode_uper,    /* Implemented in terms of OCTET STRING */
    OCTET_STRING_encode_uper,
    0, /* Use generic outmost tag fetcher */
    asn_DEF_GeneralString_tags,
    sizeof(asn_DEF_GeneralString_tags)
    / sizeof(asn_DEF_GeneralString_tags[0]) - 1,
    asn_DEF_GeneralString_tags,
    sizeof(asn_DEF_GeneralString_tags)
    / sizeof(asn_DEF_GeneralString_tags[0]),
    0,    /* No PER visible constraints */
    0, 0,    /* No members */
    0    /* No specifics */
};

asn_TYPE_descriptor_t *get_GeneralString_desc(void)
{
    return &GeneralString_desc;
}
