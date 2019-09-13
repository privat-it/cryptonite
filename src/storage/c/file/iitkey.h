#ifndef __STORAGE_ITTKEY_H__
#define __STORAGE_ITTKEY_H__

#include "sign_adapter.h"
#include "dh_adapter.h"

typedef struct IITStorageCtx_st IITStorageCtx;

CRYPTONITE_EXPORT int ittkey_decode(const char *storage_name, const ByteArray *storage_body, const char *password,
        IITStorageCtx **storage);

CRYPTONITE_EXPORT int iitkey_get_sign_adapter(const IITStorageCtx *ctx, SignAdapter **sa);

CRYPTONITE_EXPORT int iitkey_get_dh_adapter(const IITStorageCtx *this, DhAdapter **dha);

CRYPTONITE_EXPORT void iitkey_free(IITStorageCtx *ctx);

#endif
