/*
 * libFuzzer harness: time-stamp response decoder (TSP, DER).
 *
 * tsresp_decode parses a TimeStampResp from an untrusted source.
 */

#include <stddef.h>
#include <stdint.h>

#include "byte_array.h"
#include "cryptonite_errors.h"
#include "stacktrace.h"
#include "tsp_response.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ByteArray *in = NULL;
    TimeStampResp_t *resp = NULL;

    if (size == 0) {
        return 0;
    }

    in = ba_alloc_from_uint8(data, size);
    resp = tsresp_alloc();

    if (in != NULL && resp != NULL) {
        tsresp_decode(resp, in);
    }

    tsresp_free(resp);
    ba_free(in);
    stacktrace_free_current();
    return 0;
}
