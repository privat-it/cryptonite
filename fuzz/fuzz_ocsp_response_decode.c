/*
 * libFuzzer harness: OCSP response decoder (DER).
 *
 * ocspresp_decode parses an OCSPResponse from an untrusted source.
 */

#include <stddef.h>
#include <stdint.h>

#include "byte_array.h"
#include "cryptonite_errors.h"
#include "ocsp_response.h"
#include "stacktrace.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ByteArray *in = NULL;
    OCSPResponse_t *resp = NULL;

    if (size == 0) {
        return 0;
    }

    in = ba_alloc_from_uint8(data, size);
    resp = ocspresp_alloc();

    if (in != NULL && resp != NULL) {
        ocspresp_decode(resp, in);
    }

    ocspresp_free(resp);
    ba_free(in);
    stacktrace_free_current();
    return 0;
}
