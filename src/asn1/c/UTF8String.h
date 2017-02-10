/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _UTF8String_H_
#define    _UTF8String_H_

#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef OCTET_STRING_t UTF8String_t;    /* Implemented via OCTET STRING */

extern asn_TYPE_descriptor_t UTF8String_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_UTF8String_desc(void);

asn_struct_print_f UTF8String_print;
asn_constr_check_f UTF8String_constraint;

/*
 * Returns length of the given UTF-8 string in characters,
 * or a negative error code:
 * -1:    UTF-8 sequence truncated
 * -2:    Illegal UTF-8 sequence start
 * -3:    Continuation expectation failed
 * -4:    Not minimal length encoding
 * -5:    Invalid arguments
 */
CRYPTONITE_EXPORT ssize_t   UTF8String_length(const UTF8String_t *st);

/*
 * Convert the UTF-8 string into a sequence of wide characters.
 * Returns the number of characters necessary.
 * Returned value might be greater than dstlen.
 * In case of conversion error, 0 is returned.
 *
 * If st points to a valid UTF-8 string, calling
 *     UTF8String_to_wcs(st, 0, 0);
 * is equivalent to
 *     UTF8String_length(const UTF8String_t *st);
 */
CRYPTONITE_EXPORT size_t UTF8String_to_wcs(const UTF8String_t *st, uint32_t *dst, size_t dstlen);

#ifdef __cplusplus
}
#endif

#endif
