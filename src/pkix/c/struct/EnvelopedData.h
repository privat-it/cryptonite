/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _EnvelopedData_H_
#define    _EnvelopedData_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CMSVersion.h"
#include "RecipientInfos.h"
#include "EncryptedContentInfo.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct OriginatorInfo;
struct Attributes;

/* EnvelopedData */
typedef struct EnvelopedData {
    CMSVersion_t     version;
    struct OriginatorInfo    *originatorInfo    /* OPTIONAL */;
    RecipientInfos_t     recipientInfos;
    EncryptedContentInfo_t     encryptedContentInfo;
    struct Attributes    *unprotectedAttrs    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} EnvelopedData_t;

/* Implementation */
extern asn_TYPE_descriptor_t EnvelopedData_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_EnvelopedData_desc(void);

#ifdef __cplusplus
}
#endif

#endif
