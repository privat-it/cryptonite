/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ECPrivateKey_H_
#define    _ECPrivateKey_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Version.h"
#include "OCTET_STRING.h"
#include "BIT_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ECParameters;

/* ECPrivateKey */
typedef struct ECPrivateKey {
    Version_t     version;
    OCTET_STRING_t     privateKey;
    struct ECParameters    *parameters    /* OPTIONAL */;
    BIT_STRING_t    *publicKey    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ECPrivateKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t ECPrivateKey_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ECPrivateKey_desc(void);

#ifdef __cplusplus
}
#endif

#endif
