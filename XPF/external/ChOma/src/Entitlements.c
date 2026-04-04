#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>

#include "CSBlob.h"
#include "MachO.h"
#include "MemoryStream.h"
#include "FileStream.h"
#include "MachOByteOrder.h"
#include "Entitlements.h"

CFDataRef get_property_list_data(CFPropertyListRef plist) {
    CFDataRef data = NULL;
    CFErrorRef error = NULL;
    
    data = CFPropertyListCreateData(
        kCFAllocatorDefault,
        plist,
        kCFPropertyListXMLFormat_v1_0,
        0,
        &error
    );
    
    if (data == NULL) {
        if (error != NULL) {
            CFShow(error);
            CFRelease(error);
        }
    }
    
    return data;
}

CFPropertyListRef create_property_list_from_file(const char *xmlFile) {
    FILE *file = fopen(xmlFile, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: failed to open entitlements file\n");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    size_t entitlementsSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    void *entitlements = malloc(entitlementsSize);
    if (entitlements == NULL) {
        fprintf(stderr, "Error: failed to allocate memory for entitlements file\n");
        fclose(file);
        return NULL;
    }

    if (fread(entitlements, 1, entitlementsSize, file) != entitlementsSize) {
        fprintf(stderr, "Error: failed to read entitlements file\n");
        free(entitlements);
        fclose(file);
        return NULL;
    }

    fclose(file);
    CFDataRef entitlementsData = CFDataCreate(NULL, entitlements, entitlementsSize);
    if (entitlementsData == NULL) {
        fprintf(stderr, "Error: failed to create CFData from entitlements file\n");
        free(entitlements);
        return NULL;
    }

    CFPropertyListFormat format;
    CFErrorRef error;
    CFPropertyListRef entitlementsPlist = CFPropertyListCreateWithData(NULL, entitlementsData, kCFPropertyListMutableContainersAndLeaves, &format, &error);
    if (entitlementsPlist == NULL) {
        fprintf(stderr, "Error: failed to parse entitlements file\n");
        CFRelease(entitlementsData);
        CFRelease(error);
        free(entitlements);
        return NULL;
    }

    CFRelease(entitlementsData);
    free(entitlements);

    return entitlementsPlist;
}

CS_DecodedBlob *create_xml_entitlements_blob(const char *entitlementsFile) {

    CFPropertyListRef entitlementsPlist = create_property_list_from_file(entitlementsFile);
    if (entitlementsPlist == NULL) {
        fprintf(stderr, "Error: failed to create property list from entitlements file\n");
        return NULL;
    }

    CFDataRef entitlementsPlistData = get_property_list_data(entitlementsPlist);
    if (entitlementsPlistData == NULL) {
        fprintf(stderr, "Error: failed to convert entitlements property list to data\n");
        CFRelease(entitlementsPlist);
        return NULL;
    }

    uint32_t *genericBlob = malloc(sizeof(CSMAGIC_EMBEDDED_ENTITLEMENTS) + sizeof(uint32_t) + CFDataGetLength(entitlementsPlistData));
    if (genericBlob == NULL) {
        fprintf(stderr, "Error: failed to allocate memory for entitlements blob\n");
        CFRelease(entitlementsPlist);
        CFRelease(entitlementsPlistData);
        return NULL;
    }

    // Messy, but it works
    *genericBlob = HOST_TO_BIG(CSMAGIC_EMBEDDED_ENTITLEMENTS);
    uint32_t totalSize = sizeof(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS) + sizeof(uint32_t) + CFDataGetLength(entitlementsPlistData);
    *(genericBlob + 1) = HOST_TO_BIG(totalSize);
    memcpy((char *)genericBlob + sizeof(CSMAGIC_EMBEDDED_ENTITLEMENTS) + sizeof(uint32_t), CFDataGetBytePtr(entitlementsPlistData), CFDataGetLength(entitlementsPlistData));

    CS_DecodedBlob *entitlementsBlob = csd_blob_init(CSSLOT_ENTITLEMENTS, (CS_GenericBlob *)genericBlob);
    if (entitlementsBlob == NULL) {
        fprintf(stderr, "Error: failed to create entitlements blob\n");
        free(genericBlob);
    }

    CFRelease(entitlementsPlist);
    CFRelease(entitlementsPlistData);

    return entitlementsBlob;
}

enum EntitlementType {
    ENTITLEMENT_TYPE_BOOL,
    ENTITLEMENT_TYPE_INT,
    ENTITLEMENT_TYPE_STRING,
    ENTITLEMENT_TYPE_ARRAY,
};

enum ArrayType {
    ARRAY_TYPE_STRING,
    ARRAY_TYPE_INT,
};

typedef struct {
    uint32_t nItems;
    enum ArrayType type;
    void *items;
} EntitlementArray;

typedef struct {
    enum EntitlementType type;
    union {
        bool boolValue;
        int intValue;
        char *stringValue;
        EntitlementArray arrayValue;
    };
} EntitlementValue;

typedef struct {
    char *key;
    EntitlementValue value;
} Entitlement;

typedef struct {
    uint32_t nEntitlements;
    Entitlement *entitlements;
} Entitlements;

void print_entitlement_information(Entitlement *entitlement) {
    printf("Key: %s\n", entitlement->key);
    switch (entitlement->value.type) {
        case ENTITLEMENT_TYPE_BOOL:
            printf("Value: %s\n", entitlement->value.boolValue ? "true" : "false");
            break;
        case ENTITLEMENT_TYPE_INT:
            printf("Value: %d\n", entitlement->value.intValue);
            break;
        case ENTITLEMENT_TYPE_STRING:
            printf("Value: %s\n", entitlement->value.stringValue);
            break;
        case ENTITLEMENT_TYPE_ARRAY:
            printf("Values:\n");
            for (int i = 0; i < entitlement->value.arrayValue.nItems; i++) {
                printf("%d: %s\n", i + 1, ((char **)entitlement->value.arrayValue.items)[i]);
            }
            break;
    }
}

DEREncodedItem *der_encode_array(EntitlementArray array) {
    // Encode each item in the array, then create a sequence of the items
    DEREncodedItem **items = malloc(sizeof(DEREncodedItem *) * array.nItems);
    for (int i = 0; i < array.nItems; i++) {
        // Encode the item
        if (array.type == ARRAY_TYPE_STRING) {
            items[i] = der_encode_utf8_string(((char **)array.items)[i]);
        } else {
            items[i] = der_encode_integer(((int *)array.items)[i]);
        }
    }

    // Create a sequence of the items
    DEREncodedItem *sequence = der_encode_sequence(items, array.nItems);
    if (sequence == NULL) {
        fprintf(stderr, "Error: failed to encode sequence\n");
        return NULL;
    }

    // Free the encoded items
    for (int i = 0; i < array.nItems; i++) {
        der_free_encoded_item(items[i]);
    }
    free(items);

    return sequence;
}

DEREncodedItem *der_encode_entitlement(Entitlement entitlement) {
    if (!entitlement.key) {
        fprintf(stderr, "Error: missing entitlement key\n");
        return NULL;
    }

    DEREncodedItem *key = der_encode_utf8_string(entitlement.key);
    if (key == NULL) {
        fprintf(stderr, "Error: failed to encode entitlement key\n");
        return NULL;
    }
    DEREncodedItem *value = NULL;
    switch (entitlement.value.type) {
        case ENTITLEMENT_TYPE_BOOL:
            value = der_encode_boolean(entitlement.value.boolValue);
            break;
        case ENTITLEMENT_TYPE_INT:
            value = der_encode_integer(entitlement.value.intValue);
            break;
        case ENTITLEMENT_TYPE_STRING:
            value = der_encode_utf8_string(entitlement.value.stringValue);
            break;
        case ENTITLEMENT_TYPE_ARRAY:
            value = der_encode_array(entitlement.value.arrayValue);
            break;
    }

    if (value == NULL) {
        fprintf(stderr, "Error: failed to encode entitlement value\n");
        der_free_encoded_item(key);
        return NULL;
    }

    DEREncodedItem *items[] = {key, value};

    DEREncodedItem *sequence = der_encode_sequence(items, 2);
    if (sequence == NULL) {
        fprintf(stderr, "Error: failed to encode sequence\n");
        der_free_encoded_item(key);
        der_free_encoded_item(value);
        return NULL;
    }

    der_free_encoded_item(key);
    der_free_encoded_item(value);

    return sequence;
}

DEREncodedItem *der_encode_entitlements(DEREncodedItem *entitlements[], uint32_t nEntitlements) {
    DEREncodedItem *entitlementsSet = der_encode_set(entitlements, nEntitlements);
    if (entitlementsSet == NULL) {
        fprintf(stderr, "Error: failed to encode set of entitlements\n");
        return NULL;
    }

    for(int i = 0; i < nEntitlements; i++) {
        der_free_encoded_item(entitlements[i]);
    }

    return entitlementsSet;
}

static void append_to_entitlements(const void* key, const void* value, void* context) {
    Entitlements *entitlements = (Entitlements *)context;

    CFStringRef keyString = (CFStringRef)key;
    CFIndex keyLength = CFStringGetLength(keyString);
    CFIndex maxSize = CFStringGetMaximumSizeForEncoding(keyLength, kCFStringEncodingUTF8);
    char *keyCString = malloc(maxSize);
    if (keyCString == NULL) {
        fprintf(stderr, "Error: failed to allocate memory for entitlement key\n");
        return;
    }

    if (!CFStringGetCString(keyString, keyCString, maxSize, kCFStringEncodingUTF8)) {
        fprintf(stderr, "Error: failed to convert entitlement key to C string\n");
        free(keyCString);
        return;
    }

    EntitlementValue entitlementValue;

    CFTypeID valueType = CFGetTypeID(value);
    if (valueType == CFBooleanGetTypeID()) {
        entitlementValue.type = ENTITLEMENT_TYPE_BOOL;
        entitlementValue.boolValue = CFBooleanGetValue((CFBooleanRef)value);
    } else if (valueType == CFNumberGetTypeID()) {
        entitlementValue.type = ENTITLEMENT_TYPE_INT;
        CFNumberGetValue((CFNumberRef)value, kCFNumberSInt32Type, &entitlementValue.intValue);
    } else if (valueType == CFStringGetTypeID()) {
        entitlementValue.type = ENTITLEMENT_TYPE_STRING;
        CFIndex valueLength = CFStringGetLength((CFStringRef)value);
        CFIndex maxSize = CFStringGetMaximumSizeForEncoding(valueLength, kCFStringEncodingUTF8);
        char *valueCString = malloc(maxSize);
        if (valueCString == NULL) {
            fprintf(stderr, "Error: failed to allocate memory for entitlement value\n");
            free(keyCString);
            return;
        }

        if (!CFStringGetCString((CFStringRef)value, valueCString, maxSize, kCFStringEncodingUTF8)) {
            fprintf(stderr, "Error: failed to convert entitlement value to C string\n");
            free(keyCString);
            free(valueCString);
            return;
        }

        entitlementValue.stringValue = valueCString;
    } else if (valueType == CFArrayGetTypeID()) {
        entitlementValue.type = ENTITLEMENT_TYPE_ARRAY;
        CFArrayRef array = (CFArrayRef)value;
        CFIndex nItems = CFArrayGetCount(array);
        char **items = malloc(sizeof(char *) * nItems);
        if (items == NULL) {
            fprintf(stderr, "Error: failed to allocate memory for entitlement array\n");
            free(keyCString);
            return;
        }

        for (int i = 0; i < nItems; i++) {
            CFStringRef item = (CFStringRef)CFArrayGetValueAtIndex(array, i);
            CFIndex itemLength = CFStringGetLength(item);
            CFIndex maxSize = CFStringGetMaximumSizeForEncoding(itemLength, kCFStringEncodingUTF8);
            char *itemCString = malloc(maxSize);
            if (itemCString == NULL) {
                fprintf(stderr, "Error: failed to allocate memory for entitlement\n");
                for (int j = 0; j < i; j++) {
                    free(items[j]);
                }
                free(items);
                free(keyCString);
                return;
            }
            
            if (!CFStringGetCString(item, itemCString, maxSize, kCFStringEncodingUTF8)) {
                fprintf(stderr, "Error: failed to convert entitlement to C string\n");
                for (int j = 0; j < i; j++) {
                    free(items[j]);
                }
                free(items);
                free(keyCString);
                free(itemCString);
                return;
            }

            items[i] = itemCString;
        }

        EntitlementArray arrayValue = {
            .nItems = nItems,
            .type = ARRAY_TYPE_STRING,
            .items = items,
        };

        entitlementValue.arrayValue = arrayValue;

    } else {
        fprintf(stderr, "Error: unknown entitlement value type\n");
        free(keyCString);
        return;
    }

    Entitlement newEntitlement = {
        .key = keyCString,
        .value = entitlementValue,
    };

    // print_entitlement_information(&newEntitlement);

    entitlements->entitlements[entitlements->nEntitlements] = newEntitlement;
    entitlements->nEntitlements++;
    return;
}

Entitlements *parse_entitlements_from_property_list(const char *entitlementsFile) {
    CFPropertyListRef entitlementsPlist = create_property_list_from_file(entitlementsFile);
    if (entitlementsPlist == NULL) {
        fprintf(stderr, "Error: failed to create property list from entitlements file\n");
        return NULL;
    }

    if (CFGetTypeID(entitlementsPlist) != CFDictionaryGetTypeID()) {
        fprintf(stderr, "Error: entitlements file is not a dictionary\n");
        CFRelease(entitlementsPlist);
        return NULL;
    }

    CFDictionaryRef entitlementsDict = (CFDictionaryRef)entitlementsPlist;

    CFIndex nEntitlements = CFDictionaryGetCount(entitlementsDict);

    Entitlements *entitlements = malloc(sizeof(Entitlements));
    if (entitlements == NULL) {
        fprintf(stderr, "Error: failed to allocate memory for entitlements\n");
        CFRelease(entitlementsPlist);
        return NULL;
    }

    entitlements->nEntitlements = 0;
    entitlements->entitlements = malloc(sizeof(Entitlement) * nEntitlements);

    if (entitlements->entitlements == NULL) {
        fprintf(stderr, "Error: failed to allocate memory for entitlements\n");
        CFRelease(entitlementsPlist);
        free(entitlements);
        return NULL;
    }

    CFDictionaryApplyFunction(entitlementsDict, append_to_entitlements, entitlements);
    
    CFRelease(entitlementsPlist);

    return entitlements;
}

DEREncodedItem *encode_entitlements_property_list(const char *entitlementsFile) {
    Entitlements *entitlements = parse_entitlements_from_property_list(entitlementsFile);
    if (entitlements == NULL) {
        fprintf(stderr, "Error: failed to parse entitlements\n");
        return NULL;
    }

    printf("Parsed %d entitlements from entitlements file.\n", entitlements->nEntitlements);

    DEREncodedItem **encodedEntitlements = malloc(sizeof(DEREncodedItem *) * entitlements->nEntitlements);
    if (encodedEntitlements == NULL) {
        fprintf(stderr, "Error: failed to allocate memory for encoded entitlements\n");
        free(entitlements->entitlements);
        free(entitlements);
        return NULL;
    }

    for (int i = 0; i < entitlements->nEntitlements; i++) {
        encodedEntitlements[i] = der_encode_entitlement(entitlements->entitlements[i]);
        if (encodedEntitlements[i] == NULL) {
            fprintf(stderr, "Error: failed to encode entitlement\n");
            for (int j = 0; j < i; j++) {
                der_free_encoded_item(encodedEntitlements[j]);
            }
            free(encodedEntitlements);
            free(entitlements->entitlements);
            free(entitlements);
            return NULL;
        }
    }

    DEREncodedItem *entitlementsSet = der_encode_entitlements(encodedEntitlements, entitlements->nEntitlements);
    if (entitlementsSet == NULL) {
        fprintf(stderr, "Error: failed to encode entitlements\n");
        for (int i = 0; i < entitlements->nEntitlements; i++) {
            der_free_encoded_item(encodedEntitlements[i]);
        }
        free(encodedEntitlements);
        free(entitlements->entitlements);
        free(entitlements);
        return NULL;
    }
    free(encodedEntitlements);
    free(entitlements->entitlements);
    free(entitlements);

    return entitlementsSet;
}

CS_DecodedBlob *create_der_entitlements_blob(const char *entitlementsFile) {
    DEREncodedItem *entitlements = encode_entitlements_property_list(entitlementsFile);
    if (entitlements == NULL) {
        fprintf(stderr, "Error: failed to encode entitlements\n");
        return NULL;
    }

    uint32_t *genericBlob = malloc(sizeof(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS) + sizeof(uint32_t) + entitlements->length);
    if (genericBlob == NULL) {
        fprintf(stderr, "Error: failed to allocate memory for entitlements blob\n");
        der_free_encoded_item(entitlements);
        return NULL;
    }

    *genericBlob = HOST_TO_BIG(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS);
    uint32_t totalSize = sizeof(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS) + sizeof(uint32_t) + entitlements->length;
    *(genericBlob + 1) = HOST_TO_BIG(totalSize);

    memcpy((char *)genericBlob + sizeof(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS) + sizeof(uint32_t), entitlements->data, entitlements->length);

    CS_DecodedBlob *entitlementsBlob = csd_blob_init(CSSLOT_ENTITLEMENTS, (CS_GenericBlob *)genericBlob);
    if (entitlementsBlob == NULL) {
        fprintf(stderr, "Error: failed to create entitlements blob\n");
        free(genericBlob);
    }

    der_free_encoded_item(entitlements);

    return entitlementsBlob;
}