#ifndef	_SecInfo_H_
#define	_SecInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SecInfo */
typedef struct SecInfo {
	OCTET_STRING_t	 mac;
	OCTET_STRING_t	 aux;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SecInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t SecInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t* get_SecInfo_desc(void);


#ifdef __cplusplus
}
#endif

#endif	/* _SecInfo_H_ */
#include "asn_internal.h"
