/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PFX_H_
#define    _PFX_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"
#include "ContentInfo.h"
#include "constr_SEQUENCE.h"
#include "MacData.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum version {
    version_v3    = 3
} e_version;

/* Forward declarations */
struct MacData;

/* PFX */
typedef struct PFX {
    INTEGER_t     version;
    ContentInfo_t     authSafe;
    MacData_t    *macData    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PFX_t;

/* Implementation */
extern asn_TYPE_descriptor_t PFX_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PFX_desc(void);

#ifdef __cplusplus
}
#endif

#endif
