/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_ERRORS_H
#define CRYPTONITE_ERRORS_H

#ifdef  __cplusplus
extern "C" {
#endif

#define RET_OK                           0
#define RET_MEMORY_ALLOC_ERROR           1
#define RET_INVALID_PARAM                2
#define RET_VERIFY_FAILED                3
#define RET_CONTEXT_NOT_READY            4
#define RET_INVALID_CTX                  5
#define RET_INVALID_PRIVATE_KEY          6
#define RET_INVALID_PUBLIC_KEY           7
#define RET_DSTU_PRNG_LOOPED             8
#define RET_INVALID_MODE                 9
#define RET_UNSUPPORTED                  10
#define RET_INVALID_KEY_SIZE             11
#define RET_INVALID_IV_SIZE              12
#define RET_RSA_DECRYPTION_ERROR         13
#define RET_FILE_OPEN_ERROR              14
#define RET_FILE_READ_ERROR              15
#define RET_FILE_WRITE_ERROR             16
#define RET_FILE_GET_SIZE_ERROR          17
#define RET_DIR_OPEN_ERROR               18
#define RET_INVALID_CTX_MODE             19
#define RET_INVALID_HEX_STRING           20
#define RET_INVALID_DSTU_PARAM_B         21
#define RET_DATA_TOO_LONG                22
#define RET_INVALID_RSA_N                23
#define RET_INVALID_RSA_D                24
#define RET_INVALID_RSA_DMP              25
#define RET_INVALID_RSA_DMQ              26
#define RET_INVALID_RSA_IQMP             27
#define RET_INVALID_HASH_LEN             28
#define RET_INVALID_DSTU_PARAMS          29
#define RET_UNSUPPORTED_ECDSA_PARAMS     30
#define RET_CTX_ALREADY_IN_CACHE         31
#define RET_POINT_NOT_ON_CURVE           32
#define RET_INVALID_DATA_LEN             33

#ifdef  __cplusplus
}
#endif

#endif
