/*
 * libFuzzer harness: PKCS#12 store decoder.
 *
 * pkcs12_decode parses a key-container file — untrusted input that
 * flows through the ASN.1 decoder and the PFX structure parsing. The
 * password "123456" matches the test stores in src/storageUtest/
 * resources, so a seed corpus reaches the deeper parsing branches too.
 */

#include <stddef.h>
#include <stdint.h>

#include "byte_array.h"
#include "cryptonite_errors.h"
#include "pkcs12.h"
#include "stacktrace.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ByteArray *in = NULL;
    Pkcs12Ctx *storage = NULL;

    if (size == 0) {
        return 0;
    }

    in = ba_alloc_from_uint8(data, size);

    if (in != NULL) {
        pkcs12_decode(NULL, in, "123456", &storage);
    }

    pkcs12_free(storage);
    ba_free(in);
    stacktrace_free_current();   /* do not accumulate error contexts */
    return 0;
}
