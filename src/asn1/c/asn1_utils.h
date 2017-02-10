/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef SRC_ASN1_UTILS_H_
#define SRC_ASN1_UTILS_H_

#include <stdbool.h>

#include "byte_array.h"
#include "asn1_errors.h"
#include "asn1_module.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Выделяет память для asn структуры.
 */
#define ASN_ALLOC(obj) ((obj) = calloc(1, sizeof(*(obj))));                                    \
    if ((obj) == NULL) { ret = RET_MEMORY_ALLOC_ERROR;                                         \
                         ERROR_CREATE(ret);                                                    \
                         goto cleanup; }

#define    ASN_FREE(asn_DEF, ptr)                (asn_DEF)->free_struct(asn_DEF, ptr, 0)
#define    ASN_FREE_CONTENT_PTR(asn_DEF, ptr)    { if (ptr != NULL) {(asn_DEF)->free_struct(asn_DEF,ptr,1); memset(ptr, 0, sizeof *ptr);}}
#define    ASN_FREE_CONTENT_STATIC(asn_DEF, ptr) { (asn_DEF)->free_struct(asn_DEF,ptr,1); memset(ptr, 0, sizeof *ptr); }

/**
 * Возвращает байтовое представление объекта в DER-кодировании.
 * Выделяемая память требует освобождения.
 *
 * @param desc       дескриптор объекта
 * @param object     указатель на объект
 * @param encode     указатель на выделяемую память, содержащую DER-представление.
 * @param encode_len актуальный размер данных
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int asn_encode(asn_TYPE_descriptor_t *desc, const void *object,
        uint8_t **encode, size_t *encode_len);

CRYPTONITE_EXPORT int asn_encode_ba(asn_TYPE_descriptor_t *desc, const void *object, ByteArray **encoded);

/**
 * �?нициализирует asn структуру объекта из байтового представления.
 * Выделяемая память требует освобождения.
 *
 * @param desc        дескриптор объекта
 * @param object      указатель на объект
 * @param encode      указатель буфер содержащий BER-представление структуры.
 * @param encode_len  размер буфер
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int asn_decode(asn_TYPE_descriptor_t *desc, void *object, const void *encode, size_t encode_len);

CRYPTONITE_EXPORT int asn_decode_ba(asn_TYPE_descriptor_t *desc, void *object,
        const ByteArray *encode);

CRYPTONITE_EXPORT void *asn_decode_with_alloc(asn_TYPE_descriptor_t *desc, const void *encode, size_t encode_len);

CRYPTONITE_EXPORT void *asn_decode_ba_with_alloc(asn_TYPE_descriptor_t *desc, const ByteArray *encoded);

/**
 * Создает копию ASN.1 объекта заданного типа.
 *
 * @param type тип объекта
 * @param src  источник
 * @param dst  приемник
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int asn_copy(asn_TYPE_descriptor_t *type, const void *src, void *dst);

/**
* Создает копию ASN.1 объекта заданного типа.
* Выделяемая память требует освобождения.
*
* @param type тип объекта
* @param src  источник
* @param dst  приемник
*
* @return копия ASN.1 объекта заданного типа.
*/
CRYPTONITE_EXPORT void *asn_copy_with_alloc(asn_TYPE_descriptor_t *type, const void *src);

/**
 * Сравнивает две ASN.1 структуры.
 *
 * @param type тип объекта
 * @param a    сравниваемая структура
 * @param b    сравниваемая структура
 *
 * @return равны ли a и b
 */
CRYPTONITE_EXPORT bool asn_equals(asn_TYPE_descriptor_t *type, const void *a, const void *b);

CRYPTONITE_EXPORT int asn_parse_args_oid(const char *text, long **arcs, size_t *size);

/**
 * Возвращает OID по текстовому представлению.
 * (*oid == NULL) - память под ответ выделяется и требует последующего освобождения.
 * (*oid != NULL) - если память под возвращаемый объект уже выделена.
 *
 * @param src  указатель на буфер для int`ов
 * @param size размер буфера для int`ов
 * @param dst  OID
 *
 * @return код ощибки
 */
CRYPTONITE_EXPORT int asn_create_oid_from_text(const char *text, OBJECT_IDENTIFIER_t **dst);

/**
 * Возвращает OID по int`му представлению.
 * (*oid == NULL) - память под ответ выделяется и требует последующего освобождения.
 * (*oid != NULL) - если память под возвращаемый объект уже выделена.
 *
 * @param src  указатель на буфер для int`ов
 * @param size размер буфера для int`ов
 * @param dst  OID
 *
 * @return код ощибки
 */
CRYPTONITE_EXPORT int asn_create_oid(const long *src, const size_t size, OBJECT_IDENTIFIER_t **dst);

/**
 * Устанавливает OID по int`му представлению.
 *
 * @param src  указатель на буфер для int`ов
 * @param size размер буфера для int`ов
 * @param dst  OID
 *
 * @return код ощибки
 */
CRYPTONITE_EXPORT int asn_set_oid(const long *src, const size_t size, OBJECT_IDENTIFIER_t *dst);

/**
 * Создает OCTET_STRING_t из масива байт.
 * Выделяемая память требует освобождения.
 *
 * @param src масив байт
 * @param len размер входного буфера
 * @param dst OCTET_STRING_t
 *
 * @return код ощибки
 */
CRYPTONITE_EXPORT int asn_create_octstring(const void *src, const size_t len, OCTET_STRING_t **dst);

/**
 * Создает OCTET_STRING_t из масива байт.
 * Выделяемая память требует освобождения.
 *
 * @param src масив байт
 * @param dst OCTET_STRING_t
 *
 * @return код ощибки
 */
CRYPTONITE_EXPORT int asn_create_octstring_from_ba(const ByteArray *src, OCTET_STRING_t **dst);

/**
 * Создает BIT_STRING_t из байтогово масива.
 * Выделяемая память требует освобождения.
 *
 * @param src байтовый масив
 * @param len размер входного буфера
 * @param dst создаваемый BIT_STRING_t
 *
 * @return код ощибки
 */
CRYPTONITE_EXPORT int asn_create_bitstring(const void *src, const size_t len, BIT_STRING_t **dst);

/**
 * Создает BIT_STRING_t из байтогово масива.
 * Выделяемая память требует освобождения.
 *
 * @param src байтовый масив
 * @param dst создаваемый BIT_STRING_t
 *
 * @return код ощибки
 */
CRYPTONITE_EXPORT int asn_create_bitstring_from_ba(const ByteArray *src, BIT_STRING_t **dst);

CRYPTONITE_EXPORT int asn_set_bitstring_from_ba(const ByteArray *src, BIT_STRING_t *dst);
/**
 * Создает INTEGER_t из байтового представления целого числа.
 * Выделяемая память требует освобождения.
 *
 * @param src байтовое представление целого числа
 * @param len размер входного буфера
 * @param dst создаваемый INTEGER_t
 *
 * @return код ощибки
 */
CRYPTONITE_EXPORT int asn_create_integer(const void *src, const size_t len, INTEGER_t **dst);

CRYPTONITE_EXPORT int asn_create_integer_from_ba(const ByteArray *src, INTEGER_t **dst);

CRYPTONITE_EXPORT void *asn_any2type(const ANY_t *src, asn_TYPE_descriptor_t *dst_type);

/**
 * Создает ANY_t из произвольного ASN.1 объекта.
 * Выделяемая память требует освобождения.
 *
 * @param src_type тип входной структуры
 * @param src ASN.1 объект
 * @param dst создаваемый ANY_t
 *
 * @return код ощибки
 */
CRYPTONITE_EXPORT int asn_create_any(const asn_TYPE_descriptor_t *src_type, const void *src, ANY_t **dst);

/**
 * Устанавливает ANY_t из произвольного ASN.1 объекта.
 *
 * @param src_type тип входной структуры
 * @param src ASN.1 объект
 * @param dst создаваемый ANY_t
 *
 * @return код ощибки
 */
CRYPTONITE_EXPORT int asn_set_any(const asn_TYPE_descriptor_t *src_type, const void *src, ANY_t *dst);

/**
 * Создает INTEGER_t из long представления целого числа.
 * Выделяемая память требует освобождения.
 *
 * @param src long представление целого числа
 * @param dst создаваемый INTEGER_t
 *
 * @return код ощибки
 */
CRYPTONITE_EXPORT int asn_create_integer_from_long(long src, INTEGER_t **dst);

/**
 * Создает BIT_STRING_t содержаций заданный OCTET_STRING_t.
 * Выделяемая память требует освобождения.
 *
 * @param src входные данные
 * @param dst создаваемый BIT_STRING_t
 *
 * @return код ощибки
 */
CRYPTONITE_EXPORT int asn_create_bitstring_from_octstring(const OCTET_STRING_t *src, BIT_STRING_t **dst);

/**
 * Создает BIT_STRING_t содержаций заданный INTEGER_t.
 * Выделяемая память требует освобождения.
 *
 * @param src входные данные
 * @param dst создаваемый BIT_STRING_t
 *
 * @return код ощибки
 */
CRYPTONITE_EXPORT int asn_create_bitstring_from_integer(const INTEGER_t *src, BIT_STRING_t **dst);

/**
 * Возвращает массив int`ов, представляющих OID.
 *
 * @param oid  OID
 * @param arcs указатель на буфер для int`ов
 * @param size указатель на размер буфера для int`ов
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int asn_get_oid_arcs(const OBJECT_IDENTIFIER_t *oid, long **arcs, size_t *size);

/**
 * Проверяет вхождение заданного OID`а в другой (родительский) OID.
 *
 * @param oid         проверяемый OID
 * @param parent_arcs int-представление родительского OID`а
 * @param parent_size размер родительского OID`а
 *
 * @return true  - OID входит в родительский
 *         false - OID не входит в родительский
 */
CRYPTONITE_EXPORT bool asn_check_oid_parent(const OBJECT_IDENTIFIER_t *oid, const long *parent_arcs,
        size_t parent_size);

/**
 * Сравнивает два OID.
 *
 * @param oid         OID
 * @param parent_arcs указатель на буфер для int`ов
 * @param parent_size указатель на размер буфера для int`ов
 *
 * @return равны ли oid и parent_arcs
 */
CRYPTONITE_EXPORT bool asn_check_oid_equal(const OBJECT_IDENTIFIER_t *oid, const long *parent_arcs, size_t parent_size);

/**
 * Возврощает содержимое структуры OCTET STRING.
 * Выделяемая память требует освобождения.
 *
 * @param octet      указатель на объект
 * @param bytes      указатель буфер содержащий содержимое структуры.
 * @param bytes_len  размер буфера
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int asn_OCTSTRING2bytes(const OCTET_STRING_t *octet, unsigned char **bytes, size_t *bytes_len);

/**
 * Устанвливает содержимое структуры OCTET STRING.
 * Выделяемая память требует освобождения.
 *
 * @param octet      указатель на объект
 * @param bytes      указатель буфер с данными.
 * @param bytes_len  размер буфера
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int asn_bytes2OCTSTRING(OCTET_STRING_t *octet, const unsigned char *bytes, size_t bytes_len);

/**
 * Возврощает содержимое структуры INTEGER.
 * Выделяемая память требует освобождения.
 *
 * @param octet      указатель на объект
 * @param bytes      указатель буфер содержащий содержимое структуры.
 * @param bytes_len  размер буфера
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int asn_INTEGER2bytes(const INTEGER_t *integer, unsigned char **bytes, size_t *bytes_len);

/**
 * Устанвливает содержимое структуры INTEGER.
 * Выделяемая память требует освобождения.
 *
 * @param integer    указатель на объект
 * @param bytes      указатель буфер с данными.
 * @param bytes_len  размер буфера
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int asn_bytes2INTEGER(INTEGER_t *integer, const unsigned char *value, size_t len);

/**
 * Устанвливает содержимое структуры INTEGER.
 * Выделяемая память требует освобождения.
 *
 * @param bytes     указатель буфер с данными.
 * @param integer   указатель на объект
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int asn_ba2INTEGER(const ByteArray *value, INTEGER_t *integer);

/**
 * Возврощает содержимое структуры BITSTRING.
 * Выделяемая память требует освобождения.
 *
 * @param octet     указатель на объект
 * @param bytes     указатель буфер содержащий содержимое структуры.
 * @param bytes_len размер буфера
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int asn_BITSTRING2bytes(const BIT_STRING_t *string, unsigned char **bytes, size_t *bytes_len);

/**
 * Устанвливает содержимое структуры BITSTRING.
 * Выделяемая память требует освобождения.
 *
 * @param octet     указатель на объект
 * @param bytes     указатель буфер с данными.
 * @param bytes_len размер буфера
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int asn_bytes2BITSTRING(const unsigned char *bytes, BIT_STRING_t *string, size_t bytes_len);

/**
 * Устанвливает содержимое структуры BITSTRING.
 * Выделяемая память требует освобождения.
 *
 * @param string    указатель на объект
 * @param bytes     указатель буфер с данными.
 * @param bytes_len размер буфера
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int asn_BITSTRING_get_bit(const BIT_STRING_t *string, int bit_num, int *bit_value);

CRYPTONITE_EXPORT int asn_OCTSTRING2ba(const OCTET_STRING_t *os, ByteArray **ba);
CRYPTONITE_EXPORT int asn_ba2OCTSTRING(const ByteArray *ba, OCTET_STRING_t *octet);
CRYPTONITE_EXPORT int asn_ba2BITSTRING(const ByteArray *ba, BIT_STRING_t *bit_string);
CRYPTONITE_EXPORT int asn_INTEGER2ba(const INTEGER_t *in, ByteArray **ba);

CRYPTONITE_EXPORT int asn_BITSTRING2ba(const BIT_STRING_t *string, ByteArray **ba);

/** Преобразует OCTERT_STRING в объект указанного типа. */
CRYPTONITE_EXPORT int asn_OCTSTRING_to_type(const OCTET_STRING_t *src, asn_TYPE_descriptor_t *type, void **dst);

CRYPTONITE_EXPORT UTCTime_t *asn_create_curent_time(void);

CRYPTONITE_EXPORT int asn_print(FILE *stream, asn_TYPE_descriptor_t *td, void *sptr);
CRYPTONITE_EXPORT void asn_free(asn_TYPE_descriptor_t *td, void *ptr);

#ifdef __cplusplus
}
#endif

#endif
