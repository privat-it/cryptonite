/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

int main(void)
{
    utest_cryptonite_manager();
    utest_cert();
    utest_creq();
    utest_crl();
    utest_ocsp_request();
    utest_ocsp_response();
    utest_sinfo();
    utest_tsp_request();
    utest_tsp_response();
    utest_enveloped_data();
    utest_signed_data();
    utest_spki();
    utest_aids();
    utest_ext();
    utest_oids();
    utest_pkix_utils();

    utest_cert_engine();
    utest_crl_engine();

    utest_ocsp_request_engine();
    utest_ocsp_response_engine();
    utest_signed_data_engine();
    utest_signer_info_engine();
    utest_tsp_request_engine();
    utest_tsp_response_engine();

    printf("Total errors: %d\n", (int)error_count);
    stacktrace_finalize();
    fflush(stdout);

    return (error_count > 0) ? -1 : 0;
}
