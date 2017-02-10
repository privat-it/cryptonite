/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _TerminalIdentifier_H_
#define    _TerminalIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PrintableString.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TerminalIdentifier */
typedef PrintableString_t     TerminalIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t TerminalIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_TerminalIdentifier_desc(void);
asn_struct_free_f TerminalIdentifier_free;
asn_struct_print_f TerminalIdentifier_print;
asn_constr_check_f TerminalIdentifier_constraint;
ber_type_decoder_f TerminalIdentifier_decode_ber;
der_type_encoder_f TerminalIdentifier_encode_der;
xer_type_decoder_f TerminalIdentifier_decode_xer;
xer_type_encoder_f TerminalIdentifier_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
