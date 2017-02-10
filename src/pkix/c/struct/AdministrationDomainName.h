/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AdministrationDomainName_H_
#define    _AdministrationDomainName_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NumericString.h"
#include "PrintableString.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AdministrationDomainName_PR {
    AdministrationDomainName_PR_NOTHING,    /* No components present */
    AdministrationDomainName_PR_numeric,
    AdministrationDomainName_PR_printable
} AdministrationDomainName_PR;

/* AdministrationDomainName */
typedef struct AdministrationDomainName {
    AdministrationDomainName_PR present;
    union AdministrationDomainName_u {
        NumericString_t     numeric;
        PrintableString_t     printable;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} AdministrationDomainName_t;

/* Implementation */
extern asn_TYPE_descriptor_t AdministrationDomainName_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AdministrationDomainName_desc(void);

#ifdef __cplusplus
}
#endif

#endif
