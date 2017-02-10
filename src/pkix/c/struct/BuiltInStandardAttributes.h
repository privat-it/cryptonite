/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _BuiltInStandardAttributes_H_
#define    _BuiltInStandardAttributes_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NetworkAddress.h"
#include "TerminalIdentifier.h"
#include "OrganizationName.h"
#include "NumericUserIdentifier.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CountryName;
struct AdministrationDomainName;
struct PrivateDomainName;
struct PersonalName;
struct OrganizationalUnitNames;

/* BuiltInStandardAttributes */
typedef struct BuiltInStandardAttributes {
    struct CountryName    *country_name    /* OPTIONAL */;
    struct AdministrationDomainName    *administration_domain_name    /* OPTIONAL */;
    NetworkAddress_t    *network_address    /* OPTIONAL */;
    TerminalIdentifier_t    *terminal_identifier    /* OPTIONAL */;
    struct PrivateDomainName    *private_domain_name    /* OPTIONAL */;
    OrganizationName_t    *organization_name    /* OPTIONAL */;
    NumericUserIdentifier_t    *numeric_user_identifier    /* OPTIONAL */;
    struct PersonalName    *personal_name    /* OPTIONAL */;
    struct OrganizationalUnitNames    *organizational_unit_names    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} BuiltInStandardAttributes_t;

/* Implementation */
extern asn_TYPE_descriptor_t BuiltInStandardAttributes_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_BuiltInStandardAttributes_desc(void);

#ifdef __cplusplus
}
#endif

#endif
