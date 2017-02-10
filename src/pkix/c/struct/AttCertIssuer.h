/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AttCertIssuer_H_
#define    _AttCertIssuer_H_


#include "asn_application.h"

/* Including external dependencies */
#include "GeneralNames.h"
#include "V2Form.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AttCertIssuer_PR {
    AttCertIssuer_PR_NOTHING,    /* No components present */
    AttCertIssuer_PR_v1Form,
    AttCertIssuer_PR_v2Form
} AttCertIssuer_PR;

/* AttCertIssuer */
typedef struct AttCertIssuer {
    AttCertIssuer_PR present;
    union AttCertIssuer_u {
        GeneralNames_t     v1Form;
        V2Form_t     v2Form;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} AttCertIssuer_t;

/* Implementation */
extern asn_TYPE_descriptor_t AttCertIssuer_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AttCertIssuer_desc(void);

#ifdef __cplusplus
}
#endif

#endif
