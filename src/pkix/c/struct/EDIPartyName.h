/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _EDIPartyName_H_
#define    _EDIPartyName_H_


#include "asn_application.h"

/* Including external dependencies */
#include "DirectoryString.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct DirectoryString;

/* EDIPartyName */
typedef struct EDIPartyName {
    struct DirectoryString    *nameAssigner    /* OPTIONAL */;
    DirectoryString_t     partyName;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} EDIPartyName_t;

/* Implementation */
extern asn_TYPE_descriptor_t EDIPartyName_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_EDIPartyName_desc(void);

#ifdef __cplusplus
}
#endif

#endif
