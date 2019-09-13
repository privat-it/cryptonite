#ifndef	_IITKeyContainer_H_
#define	_IITKeyContainer_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "OCTET_STRING.h"
#include "IITParams.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* IITKey */
typedef struct IITKey {
	IITParams_t	 par;
	OCTET_STRING_t	 encKey;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IITKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t IITKey_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t* get_IITKey_desc(void);

#ifdef __cplusplus
}
#endif

#endif	/* _IITKeyContainer_H_ */
#include "asn_internal.h"
