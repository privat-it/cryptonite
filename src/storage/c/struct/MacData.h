/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _MacData_H_
#define    _MacData_H_


#include "asn_application.h"

/* Including external dependencies */
#include "DigestInfo.h"
#include "OCTET_STRING.h"
#include "INTEGER.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* MacData */
typedef struct MacData {
    DigestInfo_t     mac;
    OCTET_STRING_t     macSalt;
    INTEGER_t    *iterations    /* DEFAULT 1 */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} MacData_t;

/* Implementation */
extern asn_TYPE_descriptor_t MacData_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_MacData_desc(void);

#ifdef __cplusplus
}
#endif

#endif
