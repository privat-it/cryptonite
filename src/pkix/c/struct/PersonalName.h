/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PersonalName_H_
#define    _PersonalName_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PrintableString.h"
#include "constr_SET.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */

/*
 * Method of determining the components presence
 */
typedef enum PersonalName_PR {
    PersonalName_PR_surname,    /* Member surname is present */
    PersonalName_PR_given_name,    /* Member given_name is present */
    PersonalName_PR_initials,    /* Member initials is present */
    PersonalName_PR_generation_qualifier,    /* Member generation_qualifier is present */
} PersonalName_PR;

/* PersonalName */
typedef struct PersonalName {
    PrintableString_t     surname;
    PrintableString_t    *given_name    /* OPTIONAL */;
    PrintableString_t    *initials    /* OPTIONAL */;
    PrintableString_t    *generation_qualifier    /* OPTIONAL */;

    /* Presence bitmask: ASN_SET_ISPRESENT(pPersonalName, PersonalName_PR_x) */
    unsigned int _presence_map
    [((4 + (8 * sizeof(unsigned int)) - 1) / (8 * sizeof(unsigned int)))];

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PersonalName_t;

/* Implementation */
extern asn_TYPE_descriptor_t PersonalName_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PersonalName_desc(void);

#ifdef __cplusplus
}
#endif

#endif
