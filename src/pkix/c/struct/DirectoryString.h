/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _DirectoryString_H_
#define    _DirectoryString_H_


#include "asn_application.h"

/* Including external dependencies */
#include "TeletexString.h"
#include "PrintableString.h"
#include "UniversalString.h"
#include "UTF8String.h"
#include "BMPString.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DirectoryString_PR {
    DirectoryString_PR_NOTHING,    /* No components present */
    DirectoryString_PR_teletexString,
    DirectoryString_PR_printableString,
    DirectoryString_PR_universalString,
    DirectoryString_PR_utf8String,
    DirectoryString_PR_bmpString
} DirectoryString_PR;

/* DirectoryString */
typedef struct DirectoryString {
    DirectoryString_PR present;
    union DirectoryString_u {
        TeletexString_t     teletexString;
        PrintableString_t     printableString;
        UniversalString_t     universalString;
        UTF8String_t     utf8String;
        BMPString_t     bmpString;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} DirectoryString_t;

/* Implementation */
extern asn_TYPE_descriptor_t DirectoryString_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_DirectoryString_desc(void);

#ifdef __cplusplus
}
#endif

#endif
