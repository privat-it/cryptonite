/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _RecipientInfo_H_
#define    _RecipientInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "KeyTransRecipientInfo.h"
#include "KeyAgreeRecipientInfo.h"
#include "KEKRecipientInfo.h"
#include "PasswordRecipientInfo.h"
#include "OtherRecipientInfo.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RecipientInfo_PR {
    RecipientInfo_PR_NOTHING,    /* No components present */
    RecipientInfo_PR_ktri,
    RecipientInfo_PR_kari,
    RecipientInfo_PR_kekri,
    RecipientInfo_PR_pwri,
    RecipientInfo_PR_ori
} RecipientInfo_PR;

/* RecipientInfo */
typedef struct RecipientInfo {
    RecipientInfo_PR present;
    union RecipientInfo_u {
        KeyTransRecipientInfo_t     ktri;
        KeyAgreeRecipientInfo_t     kari;
        KEKRecipientInfo_t     kekri;
        PasswordRecipientInfo_t     pwri;
        OtherRecipientInfo_t     ori;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} RecipientInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t RecipientInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_RecipientInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
