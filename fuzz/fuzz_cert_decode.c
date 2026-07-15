/*
 * libFuzzer harness: X.509 certificate decoder (DER).
 *
 * cert_decode parses untrusted data from the outside world, so the
 * ASN.1 decoder's resilience to malformed input is critical. On a
 * successful parse the reverse encoding is exercised as well.
 */

#include <stddef.h>
#include <stdint.h>

#include "byte_array.h"
#include "cert.h"
#include "cryptonite_errors.h"
#include "stacktrace.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ByteArray *in = NULL;
    ByteArray *out = NULL;
    Certificate_t *cert = NULL;

    if (size == 0) {
        return 0;
    }

    in = ba_alloc_from_uint8(data, size);
    cert = cert_alloc();

    if (in != NULL && cert != NULL && cert_decode(cert, in) == RET_OK) {
        cert_encode(cert, &out);
    }

    cert_free(cert);
    ba_free(in);
    ba_free(out);
    stacktrace_free_current();   /* do not accumulate error contexts */
    return 0;
}
