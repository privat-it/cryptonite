/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_API_OIDS_H
#define CRYPTONITE_PKI_API_OIDS_H

#include <stdint.h>
#include "OBJECT_IDENTIFIER.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup pkix_oids Стандартні об'єктні ідентифікатори
 * @{
 */

/**
 * Таблиця 1.
 * Об'єктний ідентифікатор інфраструктури відкритих ключів.
 */

typedef enum OidId_st {
    OID_PKI_ID                                              = 0,      /* 1.2.804.2.1.1.1 */
    OID_PKI_ALG_ID                                          = 1,      /* 1.2.804.2.1.1.1.1 */
    OID_PKI_HASH_ID                                         = 2,      /* 1.2.804.2.1.1.1.1.2 */
    OID_PKI_GOST3411_ID                                     = 3,      /* 1.2.804.2.1.1.1.1.2.1 */
    OID_PKI_HMAC_GOST3411_ID                                = 4,      /* 1.2.804.2.1.1.1.1.1.2 */
    OID_PKI_ASYM_ID                                         = 5,      /* 1.2.804.2.1.1.1.1.3 */
    OID_PKI_DSTU4145_WITH_GOST3411_ID                       = 6,      /* 1.2.804.2.1.1.1.1.3.1 */
    OID_PKI_DSTU4145_PB_LE_ID                               = 7,      /* 1.2.804.2.1.1.1.1.3.1.1 */
    OID_PKI_SPECIAL_CURVES_PB_ID                            = 8,      /* 1.2.804.2.1.1.1.1.3.1.1.1 */
    OID_PKI_DSTU4145_PB_BE_ID                               = 9,      /* 1.2.804.2.1.1.1.1.3.1.1.1.1 */
    OID_PKI_NAMED_CURVES_PB_ID                              = 10,     /* 1.2.804.2.1.1.1.1.3.1.1.2 */
    OID_PKI_M163_PB_ID                                      = 11,     /* 1.2.804.2.1.1.1.1.3.1.1.2.0 */
    OID_PKI_M167_PB_ID                                      = 12,     /* 1.2.804.2.1.1.1.1.3.1.1.2.1 */
    OID_PKI_M173_PB_ID                                      = 13,     /* 1.2.804.2.1.1.1.1.3.1.1.2.2 */
    OID_PKI_M179_PB_ID                                      = 14,     /* 1.2.804.2.1.1.1.1.3.1.1.2.3 */
    OID_PKI_M191_PB_ID                                      = 15,     /* 1.2.804.2.1.1.1.1.3.1.1.2.4 */
    OID_PKI_M233_PB_ID                                      = 16,     /* 1.2.804.2.1.1.1.1.3.1.1.2.5 */
    OID_PKI_M257_PB_ID                                      = 17,     /* 1.2.804.2.1.1.1.1.3.1.1.2.6 */
    OID_PKI_M307_PB_ID                                      = 18,     /* 1.2.804.2.1.1.1.1.3.1.1.2.7 */
    OID_PKI_M367_PB_ID                                      = 19,     /* 1.2.804.2.1.1.1.1.3.1.1.2.8 */
    OID_PKI_M431_PB_ID                                      = 20,     /* 1.2.804.2.1.1.1.1.3.1.1.2.9 */
    OID_PKI_DSTU4145_ONB_LE_ID                              = 21,     /* 1.2.804.2.1.1.1.1.3.1.2 */
    OID_PKI_SPECIAL_CURVES_ONB_ID                           = 22,     /* 1.2.804.2.1.1.1.1.3.1.2.1 */
    OID_PKI_DSTU4145_ONB_BE_ID                              = 23,     /* 1.2.804.2.1.1.1.1.3.1.2.1.1 */
    OID_PKI_NAMED_CURVES_ONB_ID                             = 24,     /* 1.2.804.2.1.1.1.1.3.1.2.2 */
    OID_PKI_M173_ONB_ID                                     = 25,     /* 1.2.804.2.1.1.1.1.3.1.2.2.0 */
    OID_PKI_M179_ONB_ID                                     = 26,     /* 1.2.804.2.1.1.1.1.3.1.2.2.1 */
    OID_PKI_M191_ONB_ID                                     = 27,     /* 1.2.804.2.1.1.1.1.3.1.2.2.2 */
    OID_PKI_M233_ONB_ID                                     = 28,     /* 1.2.804.2.1.1.1.1.3.1.2.2.3 */
    OID_PKI_M431_ONB_ID                                     = 29,     /* 1.2.804.2.1.1.1.1.3.1.2.2.4 */
    OID_PKI_SHA1_ID                                         = 30,     /* 1.3.14.3.2.26 */
    OID_PKI_SHA224_ID                                       = 31,     /* 2.16.840.1.101.3.4.2.4 */
    OID_PKI_SHA256_ID                                       = 32,     /* 2.16.840.1.101.3.4.2.1 */
    OID_PKI_SHA384_ID                                       = 33,     /* 2.16.840.1.101.3.4.2.2 */
    OID_PKI_SHA512_ID                                       = 34,     /* 2.16.840.1.101.3.4.2.3 */
    OID_GOST34310_WITH_GOST34311_ID                         = 35,     /* 1.2.804.2.1.1.1.1.3.2 */
    OID_GOST28147_DSTU_ID                                   = 36,     /* 1.2.804.2.1.1.1.1.1.1 */
    OID_GOST28147_GOST_ID                                   = 37,     /* 1.2.643.2.2.21 */
    OID_GOST28147_OFB_ID                                    = 38,     /* 1.2.804.2.1.1.1.1.1.1.2 */
    OID_GOST28147_CFB_ID                                    = 39,     /* 1.2.804.2.1.1.1.1.1.1.3 */
    OID_GOST28147_WRAP_ID                                   = 40,     /* 1.2.804.2.1.1.1.1.1.1.5 */
    OID_DH_SINGLE_PASS_COFACTOR_DH_GOST34311KDF_SCHEME_ID   = 41,     /* 1.2.804.2.1.1.1.1.3.4 */
    OID_PKI_CP_ID                                           = 42,     /* 1.2.804.2.1.1.1.2 */
    OID_PKI_UKR_EDS_CP_ID                                   = 43,     /* 1.2.804.2.1.1.1.2.1 */
    OID_PKI_TSP_POLICY_ID                                   = 44,     /* 1.2.804.2.1.1.1.2.3 */
    OID_PKI_TSP_POLICY_DSTU_PB_ID                           = 45,     /* 1.2.804.2.1.1.1.2.3.1 */
    OID_PKI_TSP_POLICY_GOST_ID                              = 46,     /* 1.2.804.2.1.1.1.2.3.2 */
    OID_PKI_TSP_POLICY_DSTU_ONB_ID                          = 47,     /* 1.2.804.2.1.1.1.2.3.3 */
    OID_PKI_EKU_ID                                          = 48,     /* 1.2.804.2.1.1.1.3 */
    OID_PKI_EKU_STAMP_ID                                    = 49,     /* 1.2.804.2.1.1.1.3.9 */
    OID_PKI_DEV_ID                                          = 50,     /* 1.2.804.2.1.1.1.11 */
    OID_CE_CRL_REASON_ID                                    = 51,     /* 2.5.29.21 */
    OID_DATA_ID                                             = 52,     /* 1.2.840.113549.1.7.1 */
    OID_SIGNED_DATA_ID                                      = 53,     /* 1.2.840.113549.1.7.2 */
    OID_ENVELOPED_DATA_ID                                   = 54,     /* 1.2.840.113549.1.7.3 */
    OID_DIG_OID_ID                                          = 55,     /* 1.2.840.113549.1.7.5 */
    OID_ENC_OID_ID                                          = 56,     /* 1.2.840.113549.1.7.6 */
    OID_EMAIL_ID                                            = 57,     /* 1.2.840.113549.1.9.1 */
    OID_UNSTRUCTURED_NAME_ID                                = 58,     /* 1.2.840.113549.1.9.2 */
    OID_CONTENT_TYPE_ID                                     = 59,     /* 1.2.840.113549.1.9.3 */
    OID_MESSAGE_DIGEST_ID                                   = 60,     /* 1.2.840.113549.1.9.4 */
    OID_SIGNING_TIME_ID                                     = 61,     /* 1.2.840.113549.1.9.5 */
    OID_COUNTER_SIGNATURE_ID                                = 62,     /* 1.2.840.113549.1.9.6 */
    OID_CHALLENGE_PASSWORD_ID                               = 63,     /* 1.2.840.113549.1.9.7 */
    OID_UNSTRUCTURED_ADDRESS_ID                             = 64,     /* 1.2.840.113549.1.9.8 */
    OID_EXTENDED_CERT_ATTR_ID                               = 65,     /* 1.2.840.113549.1.9.9 */
    OID_SIGNING_DESCRIPTION_ID                              = 66,     /* 1.2.840.113549.1.9.13 */
    OID_EXTENSION_REQUEST_ID                                = 67,     /* 1.2.840.113549.1.9.14 */
    OID_CAPABILITIES_ID                                     = 68,     /* 1.2.840.113549.1.9.15 */
    OID_OID_REGISTRY_ID                                     = 69,     /* 1.2.840.113549.1.9.16 */
    OID_FRIENDLYNAME_ID                                     = 70,     /* 1.2.840.113549.1.9.20 */
    OID_LOCALKEY_ID                                         = 71,     /* 1.2.840.113549.1.9.21 */
    OID_CERT_TYPES_ID                                       = 72,     /* 1.2.840.113549.1.9.22 */
    OID_CRL_TYPES_ID                                        = 73,     /* 1.2.840.113549.1.9.22 */
    OID_AA_SIGNING_CERTIFICATE_ID                           = 74,     /* 1.2.840.113549.1.9.16.2.12 */
    OID_AA_SIGNING_CERTIFICATE_V2_ID                        = 75,     /* 1.2.840.113549.1.9.16.2.47 */
    OID_AA_ETS_SIG_POLICY_ID                                = 76,     /* 1.2.840.113549.1.9.16.2.15 */
    OID_SPQ_ETS_URI_ID                                      = 77,     /* 1.2.840.113549.1.9.16.5.1 */
    OID_SPQ_ETS_UNITICE_ID                                  = 78,     /* 1.2.840.113549.1.9.16.5.2 */
    OID_AA_ETS_CONTENT_TIME_STAMP_ID                        = 79,     /* 1.2.840.113549.1.9.16.2.20 */
    OID_AA_SIGNATURE_TIME_STAMP_TOKEN_ID                    = 80,     /* 1.2.840.113549.1.9.16.2.14 */
    OID_CT_TST_INFO_ID                                      = 81,     /* 1.2.840.113549.1.9.16.1.4 */
    OID_AA_ETS_CERTIFICATE_REFS_ID                          = 82,     /* 1.2.840.113549.1.9.16.2.21 */
    OID_AA_ETS_REVOCATION_REFS_ID                           = 83,     /* 1.2.840.113549.1.9.16.2.22 */
    OID_AA_ETS_CERT_VALUES_ID                               = 84,     /* 1.2.840.113549.1.9.16.2.23 */
    OID_AA_ETS_REVOCATION_VALUES_ID                         = 85,     /* 1.2.840.113549.1.9.16.2.24 */
    OID_SUBJECT_DIRECTORY_ATTRIBUTES_EXTENSION_ID           = 86,     /* 2.5.29.9 */
    OID_SUBJECT_KEY_IDENTIFIER_EXTENSION_ID                 = 87,     /* 2.5.29.14 */
    OID_KEY_USAGE_EXTENSION_ID                              = 88,     /* 2.5.29.15 */
    OID_PRIVATE_KEY_USAGE_PERIOD_EXTENSION_ID               = 89,     /* 2.5.29.16 */
    OID_SUBJECT_ALT_NAME_EXTENSION_ID                       = 90,     /* 2.5.29.17 */
    OID_ISSUER_ALT_NAME_EXTENSION_ID                        = 91,     /* 2.5.29.18 */
    OID_BASIC_CONSTRAINTS_EXTENSION_ID                      = 92,     /* 2.5.29.19 */
    OID_CRL_NUMBER_EXTENSION_ID                             = 93,     /* 2.5.29.20 */
    OID_CRL_REASON_EXTENSION_ID                             = 94,     /* 2.5.29.21 */
    OID_HOLD_INSTRUCTION_CODE_EXTENSION_ID                  = 95,     /* 2.5.29.23 */
    OID_INVALIDITY_DATE_EXTENSION_ID                        = 96,     /* 2.5.29.24 */
    OID_DELTA_CRL_INDICATOR_EXTENSION_ID                    = 97,     /* 2.5.29.27 */
    OID_CERTIFICATE_ISSUER_EXTENSION_ID                     = 98,     /* 2.5.29.29 */
    OID_CRL_DISTRIBUTION_POINTS_EXTENSION_ID                = 99,     /* 2.5.29.31 */
    OID_CERTIFICATE_POLICIES_EXTENSION_ID                   = 100,    /* 2.5.29.32 */
    OID_AUTHORITY_KEY_IDENTIFIER_EXTENSION_ID               = 101,    /* 2.5.29.35 */
    OID_EXT_KEY_USAGE_EXTENSION_ID                          = 102,    /* 2.5.29.37 */
    OID_FRESHEST_CRL_EXTENSION_ID                           = 103,    /* 2.5.29.46 */
    OID_AUTHORITY_INFO_ACCESS_EXTENSION_ID                  = 104,    /* 1.3.6.1.5.5.7.1.1 */
    OID_QC_STATEMENTS_EXTENSION_ID                          = 105,    /* 1.3.6.1.5.5.7.1.3 */
    OID_SUBJECT_INFO_ACCESS_EXTENSION_ID                    = 106,    /* 1.3.6.1.5.5.7.1.11 */
    OID_OCSP_OID_ID                                         = 107,    /* 1.3.6.1.5.5.7.48.1 */
    OID_CAISSUERS_OID_ID                                    = 108,    /* 1.3.6.1.5.5.7.48.2 */
    OID_TSP_OID_ID                                          = 109,    /* 1.3.6.1.5.5.7.48.3 */
    OID_BASIC_RESPONSE_ID                                   = 110,    /* 1.3.6.1.5.5.7.48.1.1 */
    OID_NONCE_EXTENSION_ID                                  = 111,    /* 1.3.6.1.5.5.7.48.1.2 */
    OID_CRL_ID_EXTENSION_ID                                 = 112,    /* 1.3.6.1.5.5.7.48.1.3 */
    OID_ACCEPTABLE_RESPONSES_EXTENSION_ID                   = 113,    /* 1.3.6.1.5.5.7.48.1.4 */
    OID_ARCHIVE_CUTOFF_EXTENSION_ID                         = 114,    /* 1.3.6.1.5.5.7.48.1.6 */
    OID_SERVICE_LOCATOR_EXTENSION_ID                        = 115,    /* 1.3.6.1.5.5.7.48.1.7 */
    OID_KNOWLEDGE_INFORMATION_ID                            = 116,    /* 2.5.4.2 */
    OID_COMMON_NAME_ID                                      = 117,    /* 2.5.4.3 */
    OID_SURNAME_ID                                          = 118,    /* 2.5.4.4 */
    OID_SERIAL_NUMBER_ID                                    = 119,    /* 2.5.4.5 */
    OID_COUNTRY_NAME_ID                                     = 120,    /* 2.5.4.6 */
    OID_LOCALITY_NAME_ID                                    = 121,    /* 2.5.4.7 */
    OID_STATE_NAME_ID                                       = 122,    /* 2.5.4.8 */
    OID_STREET_NAME_ID                                      = 123,    /* 2.5.4.9 */
    OID_ORGANIZATION_NAME_ID                                = 124,    /* 2.5.4.10 */
    OID_ORGANIZATION_UNIT_ID                                = 125,    /* 2.5.4.11 */
    OID_TITLE_ID                                            = 126,    /* 2.5.4.12 */
    OID_DESCRIPTION_ID                                      = 127,    /* 2.5.4.13 */
    OID_BUSINESS_CATEGORY_ID                                = 128,    /* 2.5.4.15 */
    OID_POSTAL_CODE_ID                                      = 129,    /* 2.5.4.17 */
    OID_POST_OFFICE_BOX_ID                                  = 130,    /* 2.5.4.18 */
    OID_DELIVERY_NAME_ID                                    = 131,    /* 2.5.4.19 */
    OID_GIVEN_NAME_ID                                       = 132,    /* 2.5.4.42 */
    OID_OCSP_KEY_PURPOSE_ID                                 = 133,    /* 1.3.6.1.5.5.7.3.9 */
    OID_PBES2_ID                                            = 134,    /* 1.2.840.113549.1.5.13 */
    OID_PBE_WITH_SHA1_TDES_CBC_ID                           = 135,    /* 1.2.840.113549.1.12.1.3 */
    OID_DES_EDE3_CBC_ID                                     = 136,    /* 1.2.840.113549.3.7 */
    OID_KDF_ID                                              = 137,    /* 1.2.840.113549.1.5.12 */
    OID_EC_PUBLIC_KEY_TYPE_ID                               = 138,    /* 1.2.840.10045.2.1*/
    OID_ECDSA_SECP_192_R1_ID                                = 139,    /* 1.2.840.10045.3.1.1 */
    OID_ECDSA_SECP_256_R1_ID                                = 140,    /* 1.2.840.10045.3.1.7 */
    OID_ECDSA_SECP_224_R1_ID                                = 141,    /* 1.3.132.0.33 */
    OID_ECDSA_SECP_384_R1_ID                                = 142,    /* 1.3.132.0.34 */
    OID_ECDSA_SECP_521_R1_ID                                = 143,    /* 1.3.132.0.35 */
    OID_ECDSA_SECP_256_K1_ID                                = 144,    /* 1.3.132.0.10 */
    OID_ECDSA_WITH_SHA1_ID                                  = 150,    /* 1.2.840.10045.4.1 */
    OID_ECDSA_WITH_SHA224_ID                                = 151,    /* 1.2.840.10045.4.3.1 */
    OID_ECDSA_WITH_SHA256_ID                                = 152,    /* 1.2.840.10045.4.3.2 */
    OID_ECDSA_WITH_SHA384_ID                                = 153,    /* 1.2.840.10045.4.3.3 */
    OID_ECDSA_WITH_SHA512_ID                                = 154,    /* 1.2.840.10045.4.3.4 */
    OID_AES256_CBC_ID                                       = 155,    /* 2.16.840.1.101.3.4.1.42 */
    OID_PKI_HMAC_SHA1_ID                                    = 156,    /* 1.2.840.113549.2.7 */
    OID_ETSI_QCS_ID                                         = 157,    /* 0.4.0.1862.1 */
    OID_ETSI_QCS_QC_LIMIT_VALUE_ID                          = 158,    /* 0.4.0.1862.1.2 */
    OID_PKI_GOST3410_ID                                     = 159,    /* 1.2.398.3.10.1.1.1.1 */
    OID_GOST3410_KZ_ID                                      = 160,    /* 1.2.398.3.10.1.1.1.2 */
} OidId;

typedef struct OidNumbers_st {
    long *numbers;
    size_t numbers_len;
} OidNumbers;

typedef struct NameAttr_st {
    const char *name;
    OidId oid_id;
} NameAttr;

CRYPTONITE_EXPORT const OidNumbers *oids_get_supported_extention(int ind);
CRYPTONITE_EXPORT const NameAttr *oids_get_supported_name_attr(int ind);
CRYPTONITE_EXPORT const OidNumbers *oids_get_oid_numbers_by_id(OidId oid_id);
CRYPTONITE_EXPORT OidNumbers *oids_get_oid_numbers_by_oid(const OBJECT_IDENTIFIER_t *oid);
CRYPTONITE_EXPORT OidNumbers *oids_get_oid_numbers_by_str(const char *oid);
CRYPTONITE_EXPORT void oids_oid_numbers_free(OidNumbers *oid);
CRYPTONITE_EXPORT OBJECT_IDENTIFIER_t *oids_get_oid_by_id(OidId oid_id);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
