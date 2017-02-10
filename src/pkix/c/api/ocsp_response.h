/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_API_OCSP_RESPONSE_H
#define CRYPTONITE_PKI_API_OCSP_RESPONSE_H

#include "pkix_structs.h"
#include "verify_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OcspCertStatus_st {
    CertificateSerialNumber_t *serial_number;
    const char *status;
    time_t revocationTime;
    const char *revocationReason;
} OcspCertStatus;

/**
 * Створює неініціалізований об'єкт.
 *
 * @return вказівник на створений об'єкт або NULL у випадку помилки
 */
CRYPTONITE_EXPORT OCSPResponse_t *ocspresp_alloc(void);

/**
 * Вивільняє пам'ять, яку займає об'єкт.
 *
 * @param ocspresp об'єкт, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void ocspresp_free(OCSPResponse_t *ocspresp);

/**
 * Повертає байтове представлення в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param ocspresp OCSP (відповідь)
 * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspresp_encode(const OCSPResponse_t *ocspresp, ByteArray **out);

/**
 * Ініціалізує OCSP (відповідь) з DER-представлення.
 *
 * @param ocspresp OCSP (відповідь)
 * @param in буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspresp_decode(OCSPResponse_t *ocspresp, const ByteArray *in);

/**
 * Повертає статус відповіді.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param ocspresp OCSP (відповідь)
 * @param status створюваний об'єкт статусу відповіді
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspresp_get_status(const OCSPResponse_t *ocspresp, OCSPResponseStatus_t **status);

/**
 * Встановлює статус відповіді.
 *
 * @param ocspresp OCSP (відповідь)
 * @param status статус відповіді
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspresp_set_status(OCSPResponse_t *ocspresp, const OCSPResponseStatus_t *status);

/**
 * Повертає інформацію відповіді.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param ocspresp OCSP (відповідь)
 * @param resp_bytes створюваний об'єкт інформації відповіді
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspresp_get_response_bytes(const OCSPResponse_t *ocspresp, ResponseBytes_t **resp_bytes);

/**
 * Встановлює інформацію відповіді.
 *
 * @param ocspresp OCSP (відповідь)
 * @param resp_bytes інформація відповіді
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspresp_set_response_bytes(OCSPResponse_t *ocspresp, const ResponseBytes_t *resp_bytes);

CRYPTONITE_EXPORT int ocspresp_get_certs(const OCSPResponse_t *ocspresp, Certificate_t ***certs, int *certs_len);

CRYPTONITE_EXPORT int ocspresp_get_responder_id(const OCSPResponse_t *ocspresp, ResponderID_t **responderID);

CRYPTONITE_EXPORT int ocspresp_get_certs_status(const OCSPResponse_t *ocspresp, OcspCertStatus ***ocsp_cert_statuses,
        int *ocsp_cert_statuses_len);

CRYPTONITE_EXPORT void ocspresp_certs_status_free(OcspCertStatus *ocsp_cert_statuses);

/**
 * Виконує перевірку підпису відповіді.
 *
 * @param ocspresp відповідь
 * @param adapter адаптер перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspresp_verify(const OCSPResponse_t *ocspresp, VerifyAdapter *adapter);

#ifdef __cplusplus
}
#endif

#endif
