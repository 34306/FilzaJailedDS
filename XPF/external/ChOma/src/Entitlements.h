#ifndef ENTITLEMENTS_H
#define ENTITLEMENTS_H

#include "CSBlob.h"
#include "DER.h"
CS_DecodedBlob *create_xml_entitlements_blob(const char *entitlementsFile);
CS_DecodedBlob *create_der_entitlements_blob(const char *entitlementsFile);

#endif // ENTITLEMENTS_H