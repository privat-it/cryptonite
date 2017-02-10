/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PrivateKeyInfo_H_
#define    _PrivateKeyInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Version.h"
#include "AlgorithmIdentifier.h"
#include "OCTET_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Attributes;

/* PrivateKeyInfo */
typedef struct PrivateKeyInfo {
    Version_t     version;
    AlgorithmIdentifier_t     privateKeyAlgorithm;
    OCTET_STRING_t     privateKey;
    struct Attributes    *attributes    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PrivateKeyInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t PrivateKeyInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PrivateKeyInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
