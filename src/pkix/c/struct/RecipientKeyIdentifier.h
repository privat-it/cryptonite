/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _RecipientKeyIdentifier_H_
#define    _RecipientKeyIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "SubjectKeyIdentifier.h"
#include "GeneralizedTime.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct OtherKeyAttribute;

/* RecipientKeyIdentifier */
typedef struct RecipientKeyIdentifier {
    SubjectKeyIdentifier_t     subjectKeyIdentifier;
    GeneralizedTime_t    *date    /* OPTIONAL */;
    struct OtherKeyAttribute    *other    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} RecipientKeyIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t RecipientKeyIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_RecipientKeyIdentifier_desc(void);

#ifdef __cplusplus
}
#endif

#endif
