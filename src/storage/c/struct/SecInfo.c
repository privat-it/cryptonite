#include "SecInfo.h"
#include "OCTET_STRING.h"

static asn_TYPE_member_t asn_MBR_SecInfo_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SecInfo, mac),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&OCTET_STRING_desc,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"mac"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SecInfo, aux),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&OCTET_STRING_desc,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"aux"
		},
};
static const ber_tlv_tag_t asn_DEF_SecInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SecInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mac */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* aux */
};
static asn_SEQUENCE_specifics_t asn_SPC_SecInfo_specs_1 = {
	sizeof(struct SecInfo),
	offsetof(struct SecInfo, _asn_ctx),
	asn_MAP_SecInfo_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t SecInfo_desc = {
	"SecInfo",
	"SecInfo",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_SecInfo_tags_1,
	sizeof(asn_DEF_SecInfo_tags_1)
		/sizeof(asn_DEF_SecInfo_tags_1[0]), /* 1 */
	asn_DEF_SecInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_SecInfo_tags_1)
		/sizeof(asn_DEF_SecInfo_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_SecInfo_1,
	2,	/* Elements count */
	&asn_SPC_SecInfo_specs_1	/* Additional specs */
};

CRYPTONITE_EXPORT asn_TYPE_descriptor_t* get_SecInfo_desc(void)
{
	return &SecInfo_desc;
}
