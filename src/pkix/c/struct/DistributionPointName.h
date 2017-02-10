/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _DistributionPointName_H_
#define    _DistributionPointName_H_


#include "asn_application.h"

/* Including external dependencies */
#include "GeneralNames.h"
#include "RelativeDistinguishedName.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DistributionPointName_PR {
    DistributionPointName_PR_NOTHING,    /* No components present */
    DistributionPointName_PR_fullName,
    DistributionPointName_PR_nameRelativeToCRLIssuer
} DistributionPointName_PR;

/* DistributionPointName */
typedef struct DistributionPointName {
    DistributionPointName_PR present;
    union DistributionPointName_u {
        GeneralNames_t     fullName;
        RelativeDistinguishedName_t     nameRelativeToCRLIssuer;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} DistributionPointName_t;

/* Implementation */
extern asn_TYPE_descriptor_t DistributionPointName_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_DistributionPointName_desc(void);

#ifdef __cplusplus
}
#endif

#endif
