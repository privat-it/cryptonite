#include "IITParams.h"
#include "OCTET_STRING.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/IITParams.c"

static asn_TYPE_member_t asn_MBR_IITParams_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct IITParams, id),
		(ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&OBJECT_IDENTIFIER_desc,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"id"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct IITParams, sec),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&SecInfo_desc,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"sec"
		},
};
static const ber_tlv_tag_t asn_DEF_IITParams_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
};
static const asn_TYPE_tag2member_t asn_MAP_IITParams_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* id */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* sec */
};
static asn_SEQUENCE_specifics_t asn_SPC_IITParams_specs_1 = {
	sizeof(struct IITParams),
	offsetof(struct IITParams, _asn_ctx),
	asn_MAP_IITParams_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t IITParams_desc = {
	"IITParams",
	"IITParams",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_IITParams_tags_1,
	sizeof(asn_DEF_IITParams_tags_1)
		/sizeof(asn_DEF_IITParams_tags_1[0]), /* 1 */
	asn_DEF_IITParams_tags_1,	/* Same as above */
	sizeof(asn_DEF_IITParams_tags_1)
		/sizeof(asn_DEF_IITParams_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_IITParams_1,
	2,	/* Elements count */
	&asn_SPC_IITParams_specs_1	/* Additional specs */
};

CRYPTONITE_EXPORT asn_TYPE_descriptor_t* get_IITParams_desc(void)
{
	return &IITParams_desc;
}

