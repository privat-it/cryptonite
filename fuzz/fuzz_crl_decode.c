/*
 * libFuzzer harness: certificate revocation list decoder (CRL, DER).
 *
 * crl_decode parses a CertificateList from an untrusted source.
 */

#include <stddef.h>
#include <stdint.h>

#include "byte_array.h"
#include "crl.h"
#include "cryptonite_errors.h"
#include "stacktrace.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ByteArray *in = NULL;
    ByteArray *out = NULL;
    CertificateList_t *crl = NULL;

    if (size == 0) {
        return 0;
    }

    in = ba_alloc_from_uint8(data, size);
    crl = crl_alloc();

    if (in != NULL && crl != NULL && crl_decode(crl, in) == RET_OK) {
        crl_encode(crl, &out);
    }

    crl_free(crl);
    ba_free(in);
    ba_free(out);
    stacktrace_free_current();
    return 0;
}
