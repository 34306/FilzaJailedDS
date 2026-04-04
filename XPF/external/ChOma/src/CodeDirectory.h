#ifndef CODE_DIRECTORY_H
#define CODE_DIRECTORY_H

#include <stdint.h>
#include <math.h>
#include <CommonCrypto/CommonDigest.h>

#include "MachO.h"
#include "CSBlob.h"
#include "Fat.h"
#include "MachOByteOrder.h"
#include "MachOLoadCommand.h"
#include "MemoryStream.h"

// Code directory blob header
typedef struct __CodeDirectory {
	uint32_t magic;
	uint32_t length;
	uint32_t version;
	uint32_t flags;
	uint32_t hashOffset;
	uint32_t identOffset;
	uint32_t nSpecialSlots;
	uint32_t nCodeSlots;
	uint32_t codeLimit;
	uint8_t hashSize;
	uint8_t hashType;
	uint8_t platform;
	uint8_t	pageSize;
	uint32_t spare2;

	/* Version 0x20100 */
	uint32_t scatterOffset;

	/* Version 0x20200 */
	uint32_t teamOffset;
} CS_CodeDirectory
__attribute__ ((aligned(1)));

#define CS_CDHASH_LEN 20
typedef uint8_t cdhash_t[CS_CDHASH_LEN];
void print_cdhash(cdhash_t cdhash);

enum CS_HashType {
	CS_HASHTYPE_SHA160_160 = 1,
	CS_HASHTYPE_SHA256_256 = 2,
	CS_HASHTYPE_SHA256_160 = 3,
	CS_HASHTYPE_SHA384_384 = 4,
};

char *csd_code_directory_copy_identifier(CS_DecodedBlob *codeDirBlob, uint32_t *offsetOut);
char *csd_code_directory_copy_team_id(CS_DecodedBlob *codeDirBlob, uint32_t *offsetOut);
int csd_code_directory_set_team_id(CS_DecodedBlob *codeDirBlob, char *newTeamID);
int csd_code_directory_set_identifier(CS_DecodedBlob *codeDirBlob, char *newIdentifier);
uint32_t csd_code_directory_get_flags(CS_DecodedBlob *codeDirBlob);
void csd_code_directory_set_flags(CS_DecodedBlob *codeDirBlob, uint32_t flags);
uint8_t csd_code_directory_get_hash_type(CS_DecodedBlob *codeDirBlob);
void csd_code_directory_set_hash_type(CS_DecodedBlob *codeDirBlob, uint8_t hashType);
unsigned csd_code_directory_calculate_rank(CS_DecodedBlob *codeDirBlob);
int csd_code_directory_calculate_hash(CS_DecodedBlob *codeDirBlob, void *cdhashOut);
int csd_code_directory_print_content(CS_DecodedBlob *codeDirBlob, MachO *macho, bool printSlots, bool verifySlots);
int csd_code_directory_update_special_slots(CS_DecodedBlob *codeDirBlob, CS_DecodedBlob *xmlEntitlements, CS_DecodedBlob *derEntitlements, CS_DecodedBlob *requirements);
int csd_code_directory_update_code_slots(CS_DecodedBlob *codeDirBlob, MachO *macho);
CS_DecodedBlob *csd_code_directory_init(MachO *macho, int hashType, bool alternate);

#endif // CODE_DIRECTORY_H