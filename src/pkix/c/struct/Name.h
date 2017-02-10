/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Name_H_
#define    _Name_H_


#include "asn_application.h"

/* Including external dependencies */
#include "RDNSequence.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Name_PR {
    Name_PR_NOTHING,    /* No components present */
    Name_PR_rdnSequence
} Name_PR;

/* Name */
typedef struct Name {
    Name_PR present;
    union Name_u {
        RDNSequence_t     rdnSequence;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} Name_t;

/* Implementation */
extern asn_TYPE_descriptor_t Name_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Name_desc(void);

#ifdef __cplusplus
}
#endif

#endif
