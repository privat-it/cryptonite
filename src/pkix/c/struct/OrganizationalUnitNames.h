/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OrganizationalUnitNames_H_
#define    _OrganizationalUnitNames_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OrganizationalUnitName.h"
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OrganizationalUnitNames */
typedef struct OrganizationalUnitNames {
    A_SEQUENCE_OF(OrganizationalUnitName_t) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OrganizationalUnitNames_t;

/* Implementation */
extern asn_TYPE_descriptor_t OrganizationalUnitNames_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OrganizationalUnitNames_desc(void);

#ifdef __cplusplus
}
#endif

#endif
