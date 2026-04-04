#ifndef DER_H
#define DER_H

#include <stdint.h>

typedef struct {
    uint8_t tag;
    uint32_t length;
    uint8_t *data;
} DERItem;

typedef struct {
    uint8_t *data;
    uint32_t length;
} DEREncodedItem;

void der_free_encoded_item(DEREncodedItem *item);
DEREncodedItem *der_encode_boolean(bool value);
DEREncodedItem *der_encode_integer(uint32_t value);
DEREncodedItem *der_encode_utf8_string(const char *string);
DEREncodedItem *der_encode_sequence(DEREncodedItem *items[], uint32_t nItems);
DEREncodedItem *der_encode_set(DEREncodedItem *items[], uint32_t nItems);

#endif // DER_H