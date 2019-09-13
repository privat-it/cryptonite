#include "iitkey.h"
#include "Attribute.h"
#include "storage_errors.h"
#include "kdf.h"
#include "pkix_utils.h"
#include "cryptonite_manager.h"
#include "log_internal.h"
#include "pkix_macros_internal.h"
#include "gost28147.h"
#include "content_info.h"
#include "pkcs12_utils_internal.h"
#include "IITKeyContainer.h"

#undef FILE_MARKER
#define FILE_MARKER "storage/ittkey.c"


/** OID IIT KEP key params. */
const long IIT_DH_PARAMS_OID[11] = { 1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 2 };
/** OID IIT KEP key. */
const long IIT_DH_KEY_OID[11] = { 1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 3 };

struct IITStorageCtx_st {
    Pkcs12IntStorage *owner;
    Pkcs12Keypair *kprs;
    size_t            kprs_cnt;
    PrivateKeyInfo_t *dh_key;
    PrivateKeyInfo_t *sig_key;
};

static uint8_t swap_bits(uint8_t byte)
{
    int i;
    unsigned char res = 0;

    for (i = 0; i < 8; i++) {
        res |= ((byte >> i) & 0x01) << (7 - i);
    }

    return res;
}

IITKey_t *key6_alloc(void)
{
    IITKey_t *container = NULL;
    int ret = RET_OK;

    ASN_ALLOC(container);

cleanup:

    return container;
}

void key6_free(IITKey_t *container)
{
    ASN_FREE(&IITKey_desc, container);
}

int key6_decode(IITKey_t *container, const ByteArray *encode)
{
    int ret = RET_OK;

    CHECK_PARAM(container != NULL);
    CHECK_PARAM(encode != NULL);

    ASN_FREE_CONTENT_PTR(&IITKey_desc, container);

    DO(asn_decode_ba(&IITKey_desc, container, encode));

cleanup:

    return ret;
}

static IITStorageCtx *storage_alloc(Pkcs12IntStorage *storage)
{
    IITStorageCtx *key6 = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(storage != NULL);

    CALLOC_CHECKED(key6, sizeof(IITStorageCtx));

    key6->owner = storage;
    key6->kprs = NULL;
    key6->kprs_cnt = 0;
    key6->dh_key = NULL;
    key6->sig_key = NULL;

cleanup:

    return key6;
}

int iitkey_get_dh_privatekey(const PrivateKeyInfo_t *private_key, ByteArray **d)
{
    int ret = RET_OK;
    size_t i;

    BIT_STRING_t *bs_kep_key = NULL;
    Attribute_t *kep_key_attr = NULL;
    OBJECT_IDENTIFIER_t *kep_key_oid = NULL;

    ByteArray *key = NULL;
    uint8_t *buf;

    LOG_ENTRY();

    CHECK_PARAM(d != NULL);
    CHECK_PARAM(private_key != NULL);

    DO(asn_create_oid(IIT_DH_KEY_OID, sizeof(IIT_DH_KEY_OID) / sizeof(IIT_DH_KEY_OID[0]), &kep_key_oid));
    DO(get_attr_by_oid(private_key->attributes, kep_key_oid, &kep_key_attr));

    if (kep_key_attr->value.list.count > 0) {
        CHECK_NOT_NULL(bs_kep_key = asn_any2type(kep_key_attr->value.list.array[0], &BIT_STRING_desc));
    } else {
        SET_ERROR(RET_STORAGE_INVALID_KEP_KEY_ATTR);
    }

    DO(asn_BITSTRING2ba(bs_kep_key, &key));

    buf = (uint8_t *)ba_get_buf(key);
    for (i = 0; i < ba_get_len(key); i++) {
        buf[i] = swap_bits(buf[i]);
    }

    *d = key;

cleanup:

    ASN_FREE(&BIT_STRING_desc, bs_kep_key);
    ASN_FREE(&Attribute_desc, kep_key_attr);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, kep_key_oid);

    if (ret != RET_OK) {
        ba_free(key);
    }

    return ret;
}

int iitkey_get_dh_params(const PrivateKeyInfo_t *private_key, ByteArray **params)
{
    int ret = RET_OK;

    Attribute_t *iit_parms_attr = NULL;
    OBJECT_IDENTIFIER_t *iit_params_oid = NULL;

    ByteArray *attr_bytes = NULL;

    LOG_ENTRY();

    CHECK_PARAM(params != NULL);
    CHECK_PARAM(private_key != NULL);

    DO(asn_create_oid(IIT_DH_PARAMS_OID, sizeof(IIT_DH_PARAMS_OID) / sizeof(IIT_DH_PARAMS_OID[0]), &iit_params_oid));
    DO(get_attr_by_oid(private_key->attributes, iit_params_oid, &iit_parms_attr));

    if (iit_parms_attr->value.list.count > 0) {
        asn_encode_ba(&ANY_desc, iit_parms_attr->value.list.array[0], &attr_bytes);
    } else {
        SET_ERROR(RET_STORAGE_INVALID_KEP_KEY_ATTR);
    }

    *params = attr_bytes;

cleanup:

    ASN_FREE(&Attribute_desc, iit_parms_attr);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, iit_params_oid);

    if (ret != RET_OK) {
        ba_free(attr_bytes);
    }

    return ret;
}

int ittkey_decode(const char *storage_name, const ByteArray *storage_body, const char *pass, IITStorageCtx **storage)
{
    int ret = RET_OK;
    Pkcs12IntStorage *int_storage = NULL;
    IITKey_t *key6 = NULL;
    ByteArray *key = NULL;
    Gost28147Ctx *ciph_ctx = NULL;
    Gost28147Ctx *imit_ctx = NULL;
    ByteArray *encrypted = NULL;
    ByteArray *aux = NULL;
    ByteArray *mac = NULL;
    ByteArray *dk = NULL;
    ByteArray *key_mac = NULL;
    ByteArray *dh_key = NULL;
    ByteArray *dh_params = NULL;

    LOG_ENTRY();

    CHECK_PARAM(storage_body != NULL);
    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(storage != NULL);

    LOG_ENTRY();
    CHECK_NOT_NULL(int_storage = calloc(1, sizeof(Pkcs12IntStorage)));

    CHECK_NOT_NULL(key6 = key6_alloc());
    DO(key6_decode(key6, storage_body));

    DO(asn_OCTSTRING2ba(&key6->encKey, &encrypted));
    DO(asn_OCTSTRING2ba(&key6->par.sec.aux, &aux));
    DO(asn_OCTSTRING2ba(&key6->par.sec.mac, &mac));

    ba_append(aux, 0, 0, encrypted);

    DO(kdf_pbkdf1(pass, NULL, 10000, 32, PBKDF1_GOST_HASH_ID, &dk));

    CHECK_NOT_NULL(ciph_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));
    CHECK_NOT_NULL(imit_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    gost28147_init_ecb(ciph_ctx, dk);
    gost28147_decrypt(ciph_ctx, encrypted, &key);

    gost28147_init_mac(imit_ctx, dk);
    gost28147_update_mac(imit_ctx, key);
    gost28147_final_mac(imit_ctx, &key_mac);

    if (ba_cmp(key_mac, mac)) {
        SET_ERROR(RET_STORAGE_MAC_VERIFY_ERROR);
    }

    int_storage->state = FS_ACTUAL_STATE;

    CHECK_NOT_NULL(*storage = storage_alloc(int_storage));

    CHECK_NOT_NULL((*storage)->sig_key = asn_decode_ba_with_alloc(&PrivateKeyInfo_desc, key));

    if (iitkey_get_dh_privatekey((*storage)->sig_key, &dh_key) == RET_OK) {

        ASN_ALLOC((*storage)->dh_key);

        DO(asn_bytes2OCTSTRING(&(*storage)->dh_key->privateKey, ba_get_buf(dh_key), ba_get_len(dh_key)));

        iitkey_get_dh_params((*storage)->sig_key, &dh_params);

        ASN_ALLOC((*storage)->dh_key->privateKeyAlgorithm.parameters);

        DO(asn_decode(&ANY_desc, (*storage)->dh_key->privateKeyAlgorithm.parameters, ba_get_buf(dh_params),
                ba_get_len(dh_params)));

        DO(asn_set_oid(oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_PB_BE_ID)->numbers,
                oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_PB_BE_ID)->numbers_len,
                &(*storage)->dh_key->privateKeyAlgorithm.algorithm));
    }
    int_storage = NULL;

cleanup:

    free(int_storage);
    ba_free(encrypted);
    ba_free(aux);
    ba_free(mac);
    ba_free(key_mac);
    ba_free(dk);
    ba_free(dh_params);
    ba_free_private(key);
    ba_free_private(dh_key);
    gost28147_free(imit_ctx);
    gost28147_free(ciph_ctx);
    key6_free(key6);
    return ret;
}

void iitkey_free(IITStorageCtx *ctx)
{
    LOG_ENTRY();

    if (ctx) {
        free(ctx->owner);
        if (ctx->sig_key) {
            ASN_FREE(&PrivateKeyInfo_desc, ctx->sig_key);
        }
        if (ctx->dh_key) {
            ASN_FREE(&PrivateKeyInfo_desc, ctx->dh_key);
        }
        free(ctx);
    }
}

int iitkey_get_sign_adapter(const IITStorageCtx *this, SignAdapter **sa)
{
    int ret = RET_OK;
    ByteArray *privatekey = NULL;

    LOG_ENTRY();

    CHECK_PARAM(this);
    CHECK_PARAM(sa);

    if (this->sig_key == NULL) {
        SET_ERROR(RET_STORAGE_KEY_NOT_SELECTED);
    }

    CHECK_PARAM(sa != NULL);

    DO(asn_OCTSTRING2ba(&this->sig_key->privateKey, &privatekey));

    DO(sign_adapter_init_by_aid(privatekey, &this->sig_key->privateKeyAlgorithm, &this->sig_key->privateKeyAlgorithm,
            sa));


cleanup:

    ba_free_private(privatekey);

    return ret;
}

int iitkey_get_dh_adapter(const IITStorageCtx *this, DhAdapter **dha)
{
    int ret = RET_OK;
    ByteArray *priv_key = NULL;

    CHECK_PARAM(this != NULL);
    CHECK_PARAM(dha != NULL);

    if (this->dh_key == NULL) {
        SET_ERROR(RET_STORAGE_KEY_NOT_SELECTED);
    }

    DO(asn_OCTSTRING2ba(&this->dh_key->privateKey, &priv_key));

    DO(dh_adapter_init(priv_key, &this->dh_key->privateKeyAlgorithm, dha));

cleanup:


    ba_free_private(priv_key);

    return ret;
}
