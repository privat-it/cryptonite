/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AccessDescription_H_
#define    _AccessDescription_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "GeneralName.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AccessDescription */
typedef struct AccessDescription {
    OBJECT_IDENTIFIER_t     accessMethod;
    GeneralName_t     accessLocation;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} AccessDescription_t;

/* Implementation */
extern asn_TYPE_descriptor_t AccessDescription_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AccessDescription_desc(void);

#ifdef __cplusplus
}
#endif

#endif
