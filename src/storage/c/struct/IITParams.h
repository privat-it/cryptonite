#ifndef	_IITParams_H_
#define	_IITParams_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "SecInfo.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* IITParams */
typedef struct IITParams {
	OBJECT_IDENTIFIER_t	 id;
	SecInfo_t	 sec;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IITParams_t;

/* Implementation */
extern asn_TYPE_descriptor_t IITParams_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t* get_IITParams_desc(void);

#ifdef __cplusplus
}
#endif

#endif	/* _IITParams_H_ */
#include "asn_internal.h"
