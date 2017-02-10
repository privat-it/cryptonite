/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_UTEST_H
#define CRYPTONITE_UTEST_H

#include "test_utils.h"
#include "pkix_test_utils.h"

void utest_cryptonite_manager(void);
void utest_cert(void);
void utest_crl(void);
void utest_ocsp_request(void);
void utest_sinfo(void);
void utest_tsp_request(void);
void utest_tsp_response(void);
void utest_ocsp_response(void);
void utest_enveloped_data(void);
void utest_signed_data(void);
void utest_spki(void);
void utest_aids(void);
void utest_creq(void);
void utest_cert_engine(void);
void utest_ext(void);
void utest_enveloped_data_engine(void);
void utest_ocsp_request_engine(void);
void utest_ocsp_response_engine(void);
void utest_signed_data_engine(void);
void utest_signer_info_engine(void);
void utest_tsp_request_engine(void);
void utest_tsp_response_engine(void);
void utest_cinfo(void);
void utest_oids(void);
void utest_pkix_utils(void);
void utest_crl_engine(void);

#endif
