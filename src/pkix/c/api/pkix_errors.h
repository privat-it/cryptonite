/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKIX_ERRORS_H
#define CRYPTONITE_PKIX_ERRORS_H

#include "asn1_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * Коды ошибок
 */


/**
 * @defgroup errors Коди помилок
 * @{
 */

#define PKIX_ERROR_NAME_CODE                                         0x0100

/** Невизначена помилка. */
#define RET_PKIX_GENERAL_ERROR                                       (PKIX_ERROR_NAME_CODE | 0x00000001)

/** Відсутній підпис в OCSP запиті. */
#define RET_PKIX_OCSP_REQ_NO_SIGN                                    (PKIX_ERROR_NAME_CODE | 0x00000002)

/** Відсутній атрибут. */
#define RET_PKIX_ATTRIBUTE_NOT_FOUND                                 (PKIX_ERROR_NAME_CODE | 0x00000003)

/** Вихід за межі масиву. */
#define RET_PKIX_OUT_OF_BOUND_ERROR                                  (PKIX_ERROR_NAME_CODE | 0x00000004)

/** Шуканий об'єкт не знайдений. */
#define RET_PKIX_OBJ_NOT_FOUND                                       (PKIX_ERROR_NAME_CODE | 0x00000005)

/** Помилка кріпто-менеджера. */
#define RET_PKIX_CRYPTO_MANAGER_ERROR                                (PKIX_ERROR_NAME_CODE | 0x00000006)

/** Помилка ініціалізації. */
#define RET_PKIX_INITIALIZATION_ERROR                                (PKIX_ERROR_NAME_CODE | 0x00000007)

/** Внутрішня помилка роботи. */
#define RET_PKIX_INTERNAL_ERROR                                      (PKIX_ERROR_NAME_CODE | 0x00000008)

/** Помилка шифрування. */
#define RET_PKIX_CIPHER_ERROR                                        (PKIX_ERROR_NAME_CODE | 0x00000009)

/** Помилка виробки підпису. */
#define RET_PKIX_SIGN_ERROR                                          (PKIX_ERROR_NAME_CODE | 0x0000000a)

/** Помилка перевірки підпису. */
#define RET_PKIX_VERIFY_FAILED                                       (PKIX_ERROR_NAME_CODE | 0x0000000b)

/** OID, який не підтримується. */
#define RET_PKIX_UNSUPPORTED_OID                                     (PKIX_ERROR_NAME_CODE | 0x0000000c)

/** Неправильний OID. */
#define RET_PKIX_INCORRECT_OID                                       (PKIX_ERROR_NAME_CODE | 0x0000000d)

/** PKIX об'єкт, який не підтримується. */
#define RET_PKIX_UNSUPPORTED_PKIX_OBJ                                (PKIX_ERROR_NAME_CODE | 0x0000000e)

/** Неправильна структура сертифікату. */
#define RET_PKIX_INCORRECT_CERT_STRUCTURE                            (PKIX_ERROR_NAME_CODE | 0x0000000f)

/** Відсутній сертифікат. */
#define RET_PKIX_NO_CERTIFICATE                                      (PKIX_ERROR_NAME_CODE | 0x00000010)

/** Адаптер не містить сертифікат. */
#define RET_PKIX_OCSP_REQ_ADAPTER_HASNOT_CERT                        (PKIX_ERROR_NAME_CODE | 0x00000011)

/** Не є OCSP ceртифікатом. */
#define RET_PKIX_OCSP_REQ_ADAPTER_ISNOT_OCSP                         (PKIX_ERROR_NAME_CODE | 0x00000012)

/** Кореневий сертифікат не є OCSP видавцем сертифікату. */
#define RET_PKIX_OCSP_REQ_ROOTCERT_ISNOT_OCSPISSUER                  (PKIX_ERROR_NAME_CODE | 0x00000013)

/** Кореневий сертифікат не є запитувачем видавця сертифікату. */
#define RET_PKIX_OCSP_REQ_ROOTCERT_ISNOT_REQUESTORISSUER             (PKIX_ERROR_NAME_CODE | 0x00000014)

/** Кореневий сертифікат не є перевіреним сертифікатом видавця. */
#define RET_PKIX_OCSP_REQ_ROOTCERT_ISNOT_CHECKED                     (PKIX_ERROR_NAME_CODE | 0x00000015)

/** Помилка формування підпису. */
#define RET_PKIX_OCSP_REQ_GENERATION_SIGN_ERROR                      (PKIX_ERROR_NAME_CODE | 0x00000016)

/** Запит не був згенерований. */
#define RET_PKIX_OCSP_REQ_REQUEST_HASNOT_BEEN_GENERATED              (PKIX_ERROR_NAME_CODE | 0x00000017)

/** Помилка декодування responseBytes. */
#define RET_PKIX_OCSP_REQ_RESPONSE_DECODING_ERROR                    (PKIX_ERROR_NAME_CODE | 0x00000018)

/** Помилка при отриманні основної відповіді. */
#define RET_PKIX_OCSP_REQ_RESPONSE_BASIC_ERROR                       (PKIX_ERROR_NAME_CODE | 0x00000019)

/** Помилка перевірки підпису відповіді. */
#define RET_PKIX_OCSP_REQ_RESPONSE_VERIFY_ERROR                      (PKIX_ERROR_NAME_CODE | 0x0000001a)

/** Попередження: OCSPResponse не містить nextUpdate інформацію. */
#define RET_PKIX_OCSP_REQ_RESPONSE_NEXTUP_WARNING                    (PKIX_ERROR_NAME_CODE | 0x0000001b)

/** Статус OCSPResponce не є успішним. */
#define RET_PKIX_OCSP_RESP_NOT_SUCCESSFUL                            (PKIX_ERROR_NAME_CODE | 0x0000001c)

/** Вийшов час OCSPResponce. */
#define RET_PKIX_OCSP_RESP_TIMEOUT                                   (PKIX_ERROR_NAME_CODE | 0x0000001d)

/** OCSPResponce вийшов час nextUpdate. */
#define RET_PKIX_OCSP_RESP_NEXT_UPDATE_TIMEOUT                       (PKIX_ERROR_NAME_CODE | 0x0000001e)

/** OCSPResponce не містить responseBytes. */
#define RET_PKIX_OCSP_RESP_NO_BYTES                                  (PKIX_ERROR_NAME_CODE | 0x0000001f)

/** Неможливо об'єднати CRL списки. */
#define RET_PKIX_CRL_CANT_MERGE                                      (PKIX_ERROR_NAME_CODE | 0x00000020)

#define RET_PKIX_CERT_NO_QC_STATEMENT_LIMIT                          (PKIX_ERROR_NAME_CODE | 0x00000021)

/** В списку розширень немає розширень. */
#define RET_PKIX_EXT_NOT_FOUND                                       (PKIX_ERROR_NAME_CODE | 0x00000022)

#define RET_PKIX_INVALID_CTX_MODE                                    (PKIX_ERROR_NAME_CODE | 0x00000023)

#define RET_PKIX_CONTEXT_NOT_READY                                   (PKIX_ERROR_NAME_CODE | 0x00000024)
#define RET_PKIX_INVALID_MAC                                         (PKIX_ERROR_NAME_CODE | 0x00000025)
#define RET_PKIX_SA_NO_CERTIFICATE                                   (PKIX_ERROR_NAME_CODE | 0x00000026)
#define RET_PKIX_VA_NO_CERTIFICATE                                   (PKIX_ERROR_NAME_CODE | 0x00000027)

#define RET_PKIX_OCSP_RESP_INVALID_NAME_HASH                         (PKIX_ERROR_NAME_CODE | 0x00000028)
#define RET_PKIX_OCSP_RESP_INVALID_KEY_HASH                          (PKIX_ERROR_NAME_CODE | 0x00000029)
#define RET_PKIX_OCSP_REQ_NO_REQUESTOR_NAME                          (PKIX_ERROR_NAME_CODE | 0x0000002a)
#define RET_PKIX_OCSP_REQ_VERIFY_FAILED                              (PKIX_ERROR_NAME_CODE | 0x0000002b)
#define RET_PKIX_UNSUPPORTED_RESPONDER_ID                            (PKIX_ERROR_NAME_CODE | 0x0000002c)
#define RET_PKIX_SA_NOT_OCSP_CERT                                    (PKIX_ERROR_NAME_CODE | 0x0000002d)
#define RET_OCSP_REQ_NOSINGLE_REQ_EXTS                               (PKIX_ERROR_NAME_CODE | 0x0000002e)
#define RET_PKIX_OCSP_RESP_NO_CRL_REASON                             (PKIX_ERROR_NAME_CODE | 0x0000002f)

/** InternalErrorException */
#define RET_PKIX_INTERNAL_ERROR_EXCEPTION                            (PKIX_ERROR_NAME_CODE | 0x00000030)

/** MalformedRequestException */
#define RET_PKIX_MALFORMED_REQUEST_EXCEPTION                         (PKIX_ERROR_NAME_CODE | 0x00000031)

/** SigRequiredException */
#define RET_PKIX_SIG_REQUIRED_EXCEPTION                              (PKIX_ERROR_NAME_CODE | 0x00000032)

/** Не підтримуване ім'я суб'єкту типу елемента. */
#define RET_PKIX_SUBJ_NAME_UNSUPPORTED                               (PKIX_ERROR_NAME_CODE | 0x00000033)

/** Одержувач не знайдений в контейнері EnvelopedData. */
#define RET_PKIX_RECIPIENT_NOT_FOUND                                 (PKIX_ERROR_NAME_CODE | 0x00000034)

/** Контейнерні підписи, які об'єднуються, обчислені від різних даних. */
#define RET_PKIX_SDATA_WRONG_CONTENT_DATA                            (PKIX_ERROR_NAME_CODE | 0x00000035)

/** В контейнері SignedData дані не відповідають зовнішнім даним. */
#define RET_PKIX_SDATA_WRONG_EXT_DATA                                (PKIX_ERROR_NAME_CODE | 0x00000036)

/** Помилкові дані в мітці часу. */
#define RET_PKIX_WRONG_TSP_DATA                                      (PKIX_ERROR_NAME_CODE | 0x00000037)

#define RET_PKIX_UNSUPPORTED_DSTU_ELLIPTIC_CURVE                     (PKIX_ERROR_NAME_CODE | 0x00000038)

#define RET_PKIX_UNSUPPORTED_DSTU_POL_MEMBER                         (PKIX_ERROR_NAME_CODE | 0x00000039)

#define RET_PKIX_UNSUPPORTED_DSTU_ELLIPTIC_CURVE_OID                 (PKIX_ERROR_NAME_CODE | 0x0000003a)

#define RET_PKIX_GET_TIME_ERROR                                      (PKIX_ERROR_NAME_CODE | 0x0000003b)

#define RET_PKIX_CERT_NOT_BEFORE_VALIDITY_ERROR                      (PKIX_ERROR_NAME_CODE | 0x0000003c)
#define RET_PKIX_CERT_NOT_AFTER_VALIDITY_ERROR                       (PKIX_ERROR_NAME_CODE | 0x0000003d)

#define RET_PKIX_UNSUPPORTED_PKIX_TIME                               (PKIX_ERROR_NAME_CODE | 0x0000003e)

#define RET_PKIX_CINFO_NOT_DATA                                      (PKIX_ERROR_NAME_CODE | 0x0000003f)
#define RET_PKIX_CINFO_NOT_SIGNED_DATA                               (PKIX_ERROR_NAME_CODE | 0x00000040)
#define RET_PKIX_CINFO_NOT_DIGESTED_DATA                             (PKIX_ERROR_NAME_CODE | 0x00000041)
#define RET_PKIX_CINFO_NOT_ENCRYPTED_DATA                            (PKIX_ERROR_NAME_CODE | 0x00000042)
#define RET_PKIX_CINFO_NOT_ENVELOPED_DATA                            (PKIX_ERROR_NAME_CODE | 0x00000043)

#define RET_PKIX_NO_RESPONDER_ID                                     (PKIX_ERROR_NAME_CODE | 0x00000044)

#define RET_PKIX_UNSUPPORTED_SIGN_ALG                                (PKIX_ERROR_NAME_CODE | 0x00000045)
#define RET_PKIX_INVALID_UTF8_STR                                    (PKIX_ERROR_NAME_CODE | 0x00000046)

#define RET_PKIX_SDATA_CONTENT_NOT_DATA                              (PKIX_ERROR_NAME_CODE | 0x00000047)
#define RET_PKIX_SDATA_CONTENT_NOT_TST_INFO                          (PKIX_ERROR_NAME_CODE | 0x00000048)

#define RET_PKIX_SDATA_NO_MESSAGE_DIGEST_ATTR                        (PKIX_ERROR_NAME_CODE | 0x00000049)

#define RET_PKIX_SDATA_NO_SIGNERS                                    (PKIX_ERROR_NAME_CODE | 0x0000004a)
#define RET_PKIX_SDATA_NO_CONTENT                                    (PKIX_ERROR_NAME_CODE | 0x0000004b)

#define RET_PKIX_DIFFERENT_DIGEST_ALG                                (PKIX_ERROR_NAME_CODE | 0x0000004c)
#define RET_PKIX_DIFFERENT_SIGNER_IDENTIFIER                         (PKIX_ERROR_NAME_CODE | 0x0000004d)
#define RET_PKIX_UNSUPPORTED_SPKI_ALG                                (PKIX_ERROR_NAME_CODE | 0x0000004e)

#define RET_PKIX_TSP_REQ_NO_REQ_POLICY                               (PKIX_ERROR_NAME_CODE | 0x0000004f)
#define RET_PKIX_TSP_REQ_NO_NONCE                                    (PKIX_ERROR_NAME_CODE | 0x00000050)

#define RET_PKIX_TSP_RESP_NO_TS_TOKEN                                (PKIX_ERROR_NAME_CODE | 0x00000050)
#define RET_PKIX_UNSUPPORTED_DIGEST_ALG                              (PKIX_ERROR_NAME_CODE | 0x00000051)
#define RET_PKIX_UNSUPPORTED_CIPHER_ALG                              (PKIX_ERROR_NAME_CODE | 0x00000052)

#define RET_PKIX_OCSP_RESP_NO_NEXT_UPDATE                            (PKIX_ERROR_NAME_CODE | 0x00000053)
#define RET_PKIX_OCSP_RESP_NO_LAST_UPDATE                            (PKIX_ERROR_NAME_CODE | 0x00000054)
#define RET_PKIX_PUB_KEY_NOT_CORRESPOND_FOR_PRIV                     (PKIX_ERROR_NAME_CODE | 0x00000055)
#define RET_PKIX_PRIV_KEY_NOT_CORRESPOND_FOR_PARAMS                  (PKIX_ERROR_NAME_CODE | 0x00000056)
#define RET_PKIX_UNSUPPORTED_FORM_OF_PUB_KEY                         (PKIX_ERROR_NAME_CODE | 0x00000057)
#define RET_PKIX_SDATA_NO_CERT_V2                                    (PKIX_ERROR_NAME_CODE | 0x00000058)
#define RET_PKIX_SDATA_VERIFY_CERT_V2_FAILED                         (PKIX_ERROR_NAME_CODE | 0x00000059)
#define RET_PKIX_UNSUPPORTED_ISO4217_CURRENCY_CODE                   (PKIX_ERROR_NAME_CODE | 0x0000005a)
#define RET_PKIX_PASSWORD_ATTEMPTS_ENDED                             (PKIX_ERROR_NAME_CODE | 0x0000005b)
#define RET_PKIX_ENVDATA_NO_CONTENT                                  (PKIX_ERROR_NAME_CODE | 0x0000005c)
#define RET_PKIX_ENVDATA_NEED_ORIGINATOR_CERT                        (PKIX_ERROR_NAME_CODE | 0x0000005d)
#define RET_PKIX_ENVDATA_WRONG_ORIGINATOR_CERT                       (PKIX_ERROR_NAME_CODE | 0x0000005e)
#define RET_PKIX_ENVDATA_WRONG_EXTERNAL_DATA                         (PKIX_ERROR_NAME_CODE | 0x0000005f)
#define RET_PKIX_ENVDATA_NO_RECIPIENT                                (PKIX_ERROR_NAME_CODE | 0x00000060)
#define RET_PKIX_ENVDATA_NO_ENC_OID                                  (PKIX_ERROR_NAME_CODE | 0x00000061)
#define RET_PKIX_ENVDATA_NO_PRNG                                     (PKIX_ERROR_NAME_CODE | 0x00000062)

/* @} */

#ifdef __cplusplus
}
#endif

#endif
