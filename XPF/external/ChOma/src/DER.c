#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <CoreFoundation/CoreFoundation.h>

#include "MachOByteOrder.h"
#include "DER.h"

#define ASN1_CONSTRUCTED 0x20

#define ASN1_SEQUENCE 0x10
#define ASN1_SET 0x11

#define ASN1_BOOLEAN 0x01
#define ASN1_INTEGER 0x02
#define ASN1_UTF8_STRING 0x0C

// DER entitlements are a SET of SEQUENCE serialisations, each sequence being an entitlement

void der_free_encoded_item(DEREncodedItem *item) {
    free(item->data);
    free(item);
}

DEREncodedItem *der_encode_length(uint32_t length) {
    if (length <= 0x7f) {
        uint8_t *data = malloc(1);
        if (data == NULL) {
            return NULL;
        }

        data[0] = length;

        DEREncodedItem *item = malloc(sizeof(DEREncodedItem));
        if (item == NULL) {
            return NULL;
        }

        item->data = data;
        item->length = 1;

        return item;
    } else {
        uint32_t len = length;
        uint32_t lenBytes = 0;
        while (len) {
            len >>= 8;
            lenBytes++;
        }

        uint8_t *data = malloc(lenBytes + 1);
        if (data == NULL) {
            return NULL;
        }

        data[0] = 0x80 | lenBytes;
        for (uint32_t i = 1; i <= lenBytes; i++) {
            data[i] = (length >> (8 * (lenBytes - i))) & 0xff;
        }

        DEREncodedItem *item = malloc(sizeof(DEREncodedItem));
        if (item == NULL) {
            free(data);
            return NULL;
        }

        item->data = data;
        item->length = lenBytes + 1;

        return item;
    }
}

DEREncodedItem *der_encode_item(DERItem *item) {
    DEREncodedItem *length = der_encode_length(item->length);
    if (length->data == NULL) {
        return NULL;
    }

    uint32_t totalLength = 1 + length->length + item->length;
    uint8_t *data = malloc(totalLength);
    if (data == NULL) {
        der_free_encoded_item(length);
        return NULL;
    }

    data[0] = item->tag;
    memcpy(&data[1], length->data, length->length);
    memcpy(&data[1 + length->length], item->data, item->length);

    DEREncodedItem *encodedItem = malloc(sizeof(DEREncodedItem));
    if (encodedItem == NULL) {
        der_free_encoded_item(length);
        free(data);
        return NULL;
    }

    encodedItem->data = data;
    encodedItem->length = totalLength;

    der_free_encoded_item(length);

    return encodedItem;
}

DEREncodedItem *der_encode_boolean(bool value) {
    DERItem item;
    item.tag = ASN1_BOOLEAN;
    item.data = malloc(1);
    if (item.data == NULL) {
        return NULL;
    }

    item.data[0] = value;
    item.length = 1;

    return der_encode_item(&item);
}

DEREncodedItem *der_encode_integer(uint32_t value) {
    DERItem item;
    item.tag = ASN1_INTEGER;
    item.data = malloc(sizeof(uint32_t));
    if (item.data == NULL) {
        return NULL;
    }

    // Convert to big-endian
    value = HOST_TO_BIG(value);
    memcpy(item.data, &value, sizeof(uint32_t));
    item.length = 4;

    return der_encode_item(&item);
}

DEREncodedItem *der_encode_utf8_string(const char *string) {
    DERItem item;
    item.tag = ASN1_UTF8_STRING;
    item.data = (uint8_t *)string;
    item.length = strlen(string);
    
    return der_encode_item(&item);
}

DEREncodedItem *der_encode_sequence(DEREncodedItem *items[], uint32_t nItems) {
    uint8_t tag = ASN1_SEQUENCE | ASN1_CONSTRUCTED;

    uint32_t totalLength = 0;
    for (uint32_t i = 0; i < nItems; i++) {
        totalLength += items[i]->length;
    }

    DEREncodedItem *length = der_encode_length(totalLength);
    if (length == NULL) {
        return NULL;
    }

    uint32_t totalDataLength = 1 + length->length + totalLength;

    uint8_t *data = malloc(totalDataLength);
    if (data == NULL) {
        der_free_encoded_item(length);
        return NULL;
    }

    data[0] = tag;
    memcpy(&data[1], length->data, length->length);
    uint32_t offset = 1 + length->length;
    for (uint32_t i = 0; i < nItems; i++) {
        memcpy(&data[offset], items[i]->data, items[i]->length);
        offset += items[i]->length;
    }

    DEREncodedItem *encodedItem = malloc(sizeof(DEREncodedItem));
    if (encodedItem == NULL) {
        der_free_encoded_item(length);
        free(data);
        return NULL;
    }

    encodedItem->data = data;
    encodedItem->length = totalDataLength;

    der_free_encoded_item(length);

    return encodedItem;
}

DEREncodedItem *der_encode_set(DEREncodedItem *items[], uint32_t nItems) {
    uint8_t tag = ASN1_SET | ASN1_CONSTRUCTED;

    uint32_t totalLength = 0;
    for (uint32_t i = 0; i < nItems; i++) {
        totalLength += items[i]->length;
    }

    DEREncodedItem *length = der_encode_length(totalLength);
    if (length == NULL) {
        return NULL;
    }

    uint32_t totalDataLength = 1 + length->length + totalLength;

    uint8_t *data = malloc(totalDataLength);
    if (data == NULL) {
        der_free_encoded_item(length);
        return NULL;
    }

    data[0] = tag;
    memcpy(&data[1], length->data, length->length);
    uint32_t offset = 1 + length->length;
    for (uint32_t i = 0; i < nItems; i++) {
        memcpy(&data[offset], items[i]->data, items[i]->length);
        offset += items[i]->length;
    }

    DEREncodedItem *encodedItem = malloc(sizeof(DEREncodedItem));
    if (encodedItem == NULL) {
        der_free_encoded_item(length);
        free(data);
        return NULL;
    }

    encodedItem->data = data;
    encodedItem->length = totalDataLength;

    der_free_encoded_item(length);

    return encodedItem;
}