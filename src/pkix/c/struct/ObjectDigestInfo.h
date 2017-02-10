/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ObjectDigestInfo_H_
#define    _ObjectDigestInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ENUMERATED.h"
#include "OBJECT_IDENTIFIER.h"
#include "AlgorithmIdentifier.h"
#include "BIT_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum digestedObjectType {
    digestedObjectType_publicKey    = 0,
    digestedObjectType_publicKeyCert    = 1,
    digestedObjectType_otherObjectTypes    = 2
} e_digestedObjectType;

/* ObjectDigestInfo */
typedef struct ObjectDigestInfo {
    ENUMERATED_t     digestedObjectType;
    OBJECT_IDENTIFIER_t    *otherObjectTypeID    /* OPTIONAL */;
    AlgorithmIdentifier_t     digestAlgorithm;
    BIT_STRING_t     objectDigest;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ObjectDigestInfo_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t digestedObjectType_desc_2;    // (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t ObjectDigestInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ObjectDigestInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
