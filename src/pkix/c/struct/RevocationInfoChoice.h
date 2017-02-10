/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _RevocationInfoChoice_H_
#define    _RevocationInfoChoice_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CertificateList.h"
#include "OtherRevocationInfoFormat.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RevocationInfoChoice_PR {
    RevocationInfoChoice_PR_NOTHING,    /* No components present */
    RevocationInfoChoice_PR_crl,
    RevocationInfoChoice_PR_other
} RevocationInfoChoice_PR;

/* RevocationInfoChoice */
typedef struct RevocationInfoChoice {
    RevocationInfoChoice_PR present;
    union RevocationInfoChoice_u {
        CertificateList_t     crl;
        OtherRevocationInfoFormat_t     other;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} RevocationInfoChoice_t;

/* Implementation */
extern asn_TYPE_descriptor_t RevocationInfoChoice_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_RevocationInfoChoice_desc(void);

#ifdef __cplusplus
}
#endif

#endif
