/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _GeneralName_H_
#define    _GeneralName_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OtherName.h"
#include "IA5String.h"
#include "ORAddress.h"
#include "Name.h"
#include "EDIPartyName.h"
#include "OCTET_STRING.h"
#include "OBJECT_IDENTIFIER.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum GeneralName_PR {
    GeneralName_PR_NOTHING,    /* No components present */
    GeneralName_PR_otherName,
    GeneralName_PR_rfc822Name,
    GeneralName_PR_dNSName,
    GeneralName_PR_x400Address,
    GeneralName_PR_directoryName,
    GeneralName_PR_ediPartyName,
    GeneralName_PR_uniformResourceIdentifier,
    GeneralName_PR_iPAddress,
    GeneralName_PR_registeredID
} GeneralName_PR;

/* GeneralName */
typedef struct GeneralName {
    GeneralName_PR present;
    union GeneralName_u {
        OtherName_t     otherName;
        IA5String_t     rfc822Name;
        IA5String_t     dNSName;
        ORAddress_t     x400Address;
        Name_t     directoryName;
        EDIPartyName_t     ediPartyName;
        IA5String_t     uniformResourceIdentifier;
        OCTET_STRING_t     iPAddress;
        OBJECT_IDENTIFIER_t     registeredID;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} GeneralName_t;

/* Implementation */
extern asn_TYPE_descriptor_t GeneralName_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_GeneralName_desc(void);

#ifdef __cplusplus
}
#endif

#endif
