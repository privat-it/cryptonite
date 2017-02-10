/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_API_LOG_INTERNAL_H
#define CRYPTONITE_PKI_API_LOG_INTERNAL_H

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* Never log. */
    LOG_OFF = 0,
    /* Always log if loggin enable. */
    LOG_ALWAYS = 1,
    /* Log if full logging requested. */
    LOG_OPTIONAL = 2
} log_level_t;

#define LOG_FREE(_ptr) { LOG_MSG(LOG_OPTIONAL, "FREE "#_ptr); free(_ptr); _ptr = NULL; LOG_ENTRY(); }
#define LOG_ERROR_CODE(_code) LOG_INT(LOG_ALWAYS, "LOG_ERROR code", _code)
#define LOG_ERROR() LOG_INT(LOG_ALWAYS, "ERROR: some error occurred", 0);

#undef PR
#undef PR8

#define PR(...) printf(__VA_ARGS__); fflush(stdout);

# define PRE()          PR("%s: %i\n", __FILE__, __LINE__)
# define PR8(_str, _ptr, _len)  {int ii; PR(_str); for (ii = 0; ii < (int)(_len); ii++) { if (ii % 48 == 0) PR("\n"); PR("%02x", ((uint8_t *)_ptr)[ii]); } PR("\n");}

# define LOG_ERROR_INT(...)
# define LOG_ENTRY()
# define LOG_MSG(...)
# define LOG_LONG(...)
# define LOG_BYTES(...)
# define LOG_HEX(...)
# define LOG_STR(...)
# define LOG_WSTR(...)
# define LOG_INT(...)
# define LOG_RET(...)

#ifdef __cplusplus
}
#endif

#endif
