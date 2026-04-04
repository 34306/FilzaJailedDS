#include "CodeDirectory.h"
#include "CSBlob.h"
#include "Util.h"
#include "BufferedStream.h"
#include "MemoryStream.h"
#include <CommonCrypto/CommonDigest.h>
#include <stddef.h>

void print_cdhash(cdhash_t cdhash)
{
    for (int i = 0; i < sizeof(cdhash_t); i++) {
        printf("%02x", cdhash[i]);
    }
}

void csd_code_directory_read_slot_hash(CS_DecodedBlob *codeDirBlob, MachO *macho, int slot, uint8_t *slotHashOut)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    csd_blob_read(codeDirBlob, codeDir.hashOffset + (slot * codeDir.hashSize), codeDir.hashSize, slotHashOut);
}

bool code_directory_calculate_page_hash(CS_CodeDirectory *codeDir, MachO *macho, int slot, uint8_t *pageHashOut)
{
    uint32_t pageToReadSize = (uint32_t)(pow(2.0, (double)(codeDir->pageSize)));
    uint32_t pageToReadOffset = slot * pageToReadSize;

    // Special case for reading the code signature itself
    if (slot == codeDir->nCodeSlots - 1) {
        uint32_t csOffset = 0, csSize = 0;
        macho_find_code_signature_bounds(macho, &csOffset, &csSize);
        if (pageToReadOffset > csOffset) return false;
        if (!csOffset || !csSize) pageToReadSize = memory_stream_get_size(macho->stream) - pageToReadOffset;
        else pageToReadSize = csOffset - pageToReadOffset;
    }

    // Bail out when past EOF
    if ((pageToReadOffset + pageToReadSize) > memory_stream_get_size(macho_get_stream(macho))) return false;

    uint8_t page[pageToReadSize];
    if (macho_read_at_offset(macho, pageToReadOffset, pageToReadSize, page) != 0) return false;
    switch (codeDir->hashType) {
        case CS_HASHTYPE_SHA160_160: {
            CC_SHA1(page, (CC_LONG)pageToReadSize, pageHashOut);
            break;
        }

        case CS_HASHTYPE_SHA256_256:
        case CS_HASHTYPE_SHA256_160: {
            uint8_t fullHash[CC_SHA256_DIGEST_LENGTH];
            CC_SHA256(page, (CC_LONG)pageToReadSize, fullHash);
            memcpy(pageHashOut, fullHash, codeDir->hashSize);
            break;
        }

        case CS_HASHTYPE_SHA384_384: {
            uint8_t fullHash[CC_SHA384_DIGEST_LENGTH];
            CC_SHA256(page, (CC_LONG)pageToReadSize, fullHash);
            memcpy(pageHashOut, fullHash, codeDir->hashSize);
            break;
        }

        default: {
            return false;
        }
    }

    return true;
}

bool csd_code_directory_verify_code_slot(CS_DecodedBlob *codeDirBlob, MachO *macho, int slot)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    uint8_t slotHash[codeDir.hashSize];
    csd_code_directory_read_slot_hash(codeDirBlob, macho, slot, slotHash);

    uint8_t pageHash[codeDir.hashSize];
    if (!code_directory_calculate_page_hash(&codeDir, macho, slot, slotHash)) return false;

    return (memcmp(slotHash, pageHash, codeDir.hashSize) == 0);
}

bool csd_code_directory_verify_code_slots(CS_DecodedBlob *codeDirBlob, MachO *macho, int slot)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, HOST_TO_BIG_APPLIER);

    for (int i = 0; i < codeDir.nCodeSlots; i++) {
        if (!csd_code_directory_verify_code_slot(codeDirBlob, macho, i)) {
            return false;
        }
    }
    return true;
}

const char *cs_hash_type_to_string(int hashType)
{
    switch (hashType) {
    case CS_HASHTYPE_SHA160_160:
        return "SHA-1 160";
    case CS_HASHTYPE_SHA256_256:
        return "SHA-2 256";
    case CS_HASHTYPE_SHA256_160:
        return "SHA-2 160";
    case CS_HASHTYPE_SHA384_384:
        return "SHA-3 384";
    default:
        return "Unknown blob type";
    }
}

int cs_hash_type_to_length(int hashType)
{
    switch (hashType) {
    case CS_HASHTYPE_SHA160_160:
        return 0x14;
    case CS_HASHTYPE_SHA256_256:
    case CS_HASHTYPE_SHA256_160:
        return 0x20;
    case CS_HASHTYPE_SHA384_384:
        return 0x30;
    default:
        return 0;
    }
}

int cs_code_directory_get_size(int version) {
    switch (version) {
        case 0x20600: return 0x70;
        case 0x20500: return 0x60;
        case 0x20400: return 0x58;
        case 0x20300: return 0x40;
        // 0x20200 matches ChOma's CS_CodeDirectory structure
        default: return 0x34;
    }
}

const char* cs_slot_to_string(int slot)
{
    switch (slot) {
        case -11:
        return "Loaded library launch constraints hash";
        case -10:
        return "Responsible process launch constraints hash";
        case -9:
        return "Parent process launch constraints hash";
        case -8:
        return "Process launch constraints hash";
        case -7:
        return "DER entitlements hash";
        case -6:
        return "DMG signature hash";
        case -5:
        return "Entitlements hash";
        case -4:
        return "App-specific hash";
        case -3:
        return "CodeResources hash";
        case -2:
        return "Requirements blob hash";
        case -1:
        return "Info.plist hash";
        default:
        return "Page hash";
    }
}

char *csd_code_directory_copy_identifier(CS_DecodedBlob *codeDirBlob, uint32_t *offsetOut)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    if (codeDir.identOffset == 0) return NULL;

    char *identity = NULL;
    csd_blob_read_string(codeDirBlob, codeDir.identOffset, &identity);
    if (offsetOut) *offsetOut = codeDir.identOffset;
    return identity;
}

char *csd_code_directory_copy_team_id(CS_DecodedBlob *codeDirBlob, uint32_t *offsetOut)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    if (codeDir.version < 0x20200) return NULL;
    if (codeDir.teamOffset == 0) return NULL;

    char *teamId = NULL;
    csd_blob_read_string(codeDirBlob, codeDir.teamOffset, &teamId);
    if (offsetOut) *offsetOut = codeDir.teamOffset;
    return teamId;
}

int csd_code_directory_set_team_id(CS_DecodedBlob *codeDirBlob, char *newTeamID)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    size_t newTeamIDSize = strlen(newTeamID)+1;

    int32_t shift = 0;
    uint32_t initalTeamOffset = 0;
    char *previousTeamID = csd_code_directory_copy_team_id(codeDirBlob, &initalTeamOffset);
    if (previousTeamID) {
        // If there is already a TeamID, delete it
        uint32_t previousTeamIDSize = strlen(previousTeamID)+1;
        csd_blob_delete(codeDirBlob, initalTeamOffset, previousTeamIDSize);
        shift -= previousTeamIDSize;
        free(previousTeamID);
    }

    if (initalTeamOffset) {
        codeDir.teamOffset = initalTeamOffset;
    }
    else {
        uint32_t identityOffset = 0;
        char *identity = csd_code_directory_copy_identifier(codeDirBlob, &identityOffset);
        if (!identity) {
            codeDir.teamOffset = cs_code_directory_get_size(codeDir.version);
        } else {
            codeDir.teamOffset = identityOffset + strlen(identity) + 1;
            free(identity);
        }
    }

    // Insert new team ID
    csd_blob_insert(codeDirBlob, codeDir.teamOffset, newTeamIDSize, newTeamID);
    shift += newTeamIDSize;

    // Shift other offsets as needed (Since we inserted data in the middle)
    if (codeDir.hashOffset != 0 && codeDir.hashOffset > initalTeamOffset) {
        codeDir.hashOffset += shift;
    }
    if (codeDir.scatterOffset != 0 && codeDir.scatterOffset > initalTeamOffset) {
        codeDir.scatterOffset += shift;
    }

    // Write changes to codeDir struct
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, HOST_TO_BIG_APPLIER);
    csd_blob_write(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    return 0;
}

int csd_code_directory_set_identifier(CS_DecodedBlob *codeDirBlob, char *newIdentifier)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    size_t newIdentifierSize = strlen(newIdentifier)+1;

    int32_t shift = 0;
    uint32_t initialIDOffset = 0;
    char *previousIdentifier = csd_code_directory_copy_identifier(codeDirBlob, &initialIDOffset);
    if (previousIdentifier) {
        uint32_t previousIdentifierSize = strlen(previousIdentifier)+1;
        csd_blob_delete(codeDirBlob, initialIDOffset, previousIdentifierSize);
        shift -= previousIdentifierSize;
        free(previousIdentifier);
    }

    if (initialIDOffset) {
        codeDir.identOffset = initialIDOffset;
    }
    else {
        uint32_t teamOffset = 0;
        char *team = csd_code_directory_copy_team_id(codeDirBlob, &teamOffset);
        if (!team) {
            codeDir.identOffset = cs_code_directory_get_size(codeDir.version);
        } else {
            codeDir.identOffset = teamOffset - strlen(team) + 1;
            free(team);
        }
    }

    // Insert new identifier
    csd_blob_insert(codeDirBlob, codeDir.identOffset, newIdentifierSize, newIdentifier);
    shift += newIdentifierSize;

    // Shift other offsets as needed (Since we inserted data in the middle)
    if (codeDir.teamOffset != 0 && codeDir.teamOffset > initialIDOffset) {
        codeDir.teamOffset += shift;
    }
    if (codeDir.hashOffset != 0 && codeDir.hashOffset > initialIDOffset) {
        codeDir.hashOffset += shift;
    }
    if (codeDir.scatterOffset != 0 && codeDir.scatterOffset > initialIDOffset) {
        codeDir.scatterOffset += shift;
    }

    // Write changes to codeDir struct
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, HOST_TO_BIG_APPLIER);
    csd_blob_write(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    return 0;
}

uint32_t csd_code_directory_get_flags(CS_DecodedBlob *codeDirBlob)
{
    uint32_t flags = 0;
    csd_blob_read(codeDirBlob, offsetof(CS_CodeDirectory, flags), sizeof(flags), &flags);
    return BIG_TO_HOST(flags);
}

void csd_code_directory_set_flags(CS_DecodedBlob *codeDirBlob, uint32_t flags)
{
    flags = HOST_TO_BIG(flags);
    csd_blob_write(codeDirBlob, offsetof(CS_CodeDirectory, flags), sizeof(flags), &flags); 
}

uint8_t csd_code_directory_get_hash_type(CS_DecodedBlob *codeDirBlob)
{
    uint8_t hashType = 0;
    csd_blob_read(codeDirBlob, offsetof(CS_CodeDirectory, hashType), sizeof(hashType), &hashType);
    return hashType;
}

void csd_code_directory_set_hash_type(CS_DecodedBlob *codeDirBlob, uint8_t hashType)
{
    csd_blob_write(codeDirBlob, offsetof(CS_CodeDirectory, hashType), sizeof(hashType), &hashType);
}

unsigned csd_code_directory_calculate_rank(CS_DecodedBlob *codeDirBlob)
{
    // The supported hash types, ranked from least to most preferred. From XNU's
	// bsd/kern/ubc_subr.c.
	static uint32_t rankedHashTypes[] = {
		CS_HASHTYPE_SHA160_160,
		CS_HASHTYPE_SHA256_160,
		CS_HASHTYPE_SHA256_256,
		CS_HASHTYPE_SHA384_384,
	};
	// Define the rank of the code directory as its index in the array plus one.
    uint8_t type = csd_code_directory_get_hash_type(codeDirBlob);
	for (unsigned i = 0; i < sizeof(rankedHashTypes) / sizeof(rankedHashTypes[0]); i++) {
		if (rankedHashTypes[i] == type) {
			return (i + 1);
		}
	}
	return 0;
}

int csd_code_directory_calculate_hash(CS_DecodedBlob *codeDirBlob, void *cdhashOut)
{
    if (!codeDirBlob || !cdhashOut) return -1;

    // Longest possible buffer, will cut it off at the end as cdhash size is fixed
    uint8_t cdhash[CC_SHA384_DIGEST_LENGTH];

    size_t cdBlobSize = csd_blob_get_size(codeDirBlob);
    uint8_t *cdBlob = memory_stream_get_raw_pointer(codeDirBlob->stream);

    switch (csd_code_directory_get_hash_type(codeDirBlob)) {
		case CS_HASHTYPE_SHA160_160: {
			CC_SHA1(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}
		
		case CS_HASHTYPE_SHA256_256:
		case CS_HASHTYPE_SHA256_160: {
			CC_SHA256(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}

		case CS_HASHTYPE_SHA384_384: {
			CC_SHA384(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}

        default:
        return -1;
	}

    memcpy(cdhashOut, cdhash, CS_CDHASH_LEN);
    return 0;
}

int csd_code_directory_print_content(CS_DecodedBlob *codeDirBlob, MachO *macho, bool printSlots, bool verifySlots)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(codeDir), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    // Version 0x20000
    printf("Code directory:\n");
    printf("\tMagic: 0x%X\n", codeDir.magic);
    printf("\tLength: 0x%x\n", codeDir.length);
    printf("\tVersion: 0x%x\n", codeDir.version);
    printf("\tFlags: 0x%x\n", codeDir.flags);
    printf("\tHash offset: 0x%x\n", codeDir.hashOffset);

    uint32_t identifierOffset = 0;
    char *identifier = csd_code_directory_copy_identifier(codeDirBlob, &identifierOffset);
    if (identifier) {
        printf("\tIdentifier: \"%s\" (@ 0x%x)\n", identifier, identifierOffset);
        free(identifier);
    }

    printf("\tNumber of special slots: %u\n", codeDir.nSpecialSlots);
    printf("\tNumber of code slots: %u\n", codeDir.nCodeSlots);
    printf("\tCode limit: 0x%x\n", codeDir.codeLimit);
    printf("\tHash size: 0x%x\n", codeDir.hashSize);
    printf("\tHash type: %s\n", cs_hash_type_to_string(codeDir.hashType));
    printf("\tPlatform: %d\n", codeDir.platform);
    printf("\tPage size: 0x%x\n", codeDir.pageSize);

    // Version 0x20100
    if (codeDir.version >= 0x20100) {
        printf("\tScatter offset: 0x%x\n", codeDir.scatterOffset);
        uint32_t teamOffset = 0;
        char *teamId = csd_code_directory_copy_team_id(codeDirBlob, &teamOffset);
        if (teamId) {
            printf("\tTeam ID: \"%s\" (@ 0x%x)\n", teamId, teamOffset);
            free(teamId);
        }
    }

    printf("\n");
    bool codeSlotsCorrect = true;
    bool needsNewline = false;

    for (int64_t i = -((int64_t)codeDir.nSpecialSlots); i < (int64_t)codeDir.nCodeSlots; i++) {
        // Read slot
        uint8_t slotHash[codeDir.hashSize];
        csd_code_directory_read_slot_hash(codeDirBlob, macho, i, slotHash);
        if (printSlots || verifySlots) {
            // Print the slot number
            needsNewline = true;
            printf("%s%lld: ", i < 0 ? "" : " ",  i);

            print_hash(slotHash, codeDir.hashSize);

            // Check if hash is just zeroes
            bool isZero = true;
            for (int j = 0; j < codeDir.hashSize; j++) {
                if (slotHash[j] != 0) {
                    isZero = false;
                    break;
                }
            }

            // TrollStore TODO: Validate that hashes are correct
            // validateHashes(macho, specialSlots, codeDir.nSpecialSlots * codeDir.hashSize);
            // Don't print the slot name if the hash is just zeroes
            if (!isZero) {
                // Print the special slot name (if applicable)
                printf(" (%s)", cs_slot_to_string(i));
            }
        }

        if (verifySlots && i >= 0) {
            uint8_t pageHash[codeDir.hashSize];
            needsNewline = true;
            bool correct = false;
            bool calcWorked = code_directory_calculate_page_hash(&codeDir, macho, i, pageHash);
            if (calcWorked) {
                correct = (memcmp(slotHash, pageHash, codeDir.hashSize) == 0);
            }

            if (correct) {
                printf(" ✅");
            }
            else {
                codeSlotsCorrect = false;
                if (!calcWorked) {
                    printf(" ❌  (unable to calculate, probably EOF?)");
                }
                else {
                    printf(" ❌  (should be: ");
                    print_hash(pageHash, codeDir.hashSize);
                    printf(")");
                }
            }
        }

        if (needsNewline) printf("\n");
        needsNewline = false;
    }
    if (verifySlots) {
        if (codeSlotsCorrect) {
            printf("All page hashes are valid!\n");
        }
        else {
            printf("Some page hashes are invalid!\n");
        }
    }

    char cdhash[CS_CDHASH_LEN];
    if (csd_code_directory_calculate_hash(codeDirBlob, cdhash) == 0) {
        printf(" CDHash: ");
        print_hash((uint8_t *)cdhash, sizeof(cdhash));
        printf("\n");
    }

    return 0;
}

int csd_code_directory_update_special_slots(CS_DecodedBlob *codeDirBlob, CS_DecodedBlob *xmlEntitlements, CS_DecodedBlob *derEntitlements, CS_DecodedBlob *requirements) {
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(CS_CodeDirectory), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    int hashLen = 0;
    unsigned char *(*hashFunc)(const void *data, CC_LONG len, unsigned char *md) = NULL;

    switch (codeDir.hashType) {
        case CS_HASHTYPE_SHA160_160:
            hashLen = CC_SHA1_DIGEST_LENGTH;
            hashFunc = CC_SHA1;
            break;
        case CS_HASHTYPE_SHA256_160:
        case CS_HASHTYPE_SHA256_256:
            hashLen = CC_SHA256_DIGEST_LENGTH;
            hashFunc = CC_SHA256;
            break;
        case CS_HASHTYPE_SHA384_384:
            hashLen = CC_SHA384_DIGEST_LENGTH;
            hashFunc = CC_SHA384;
            break;
        default:
            break;
    }
    if (!hashLen) {
        printf("Error: unknown hash type (%d)\n", codeDir.hashType);
    }

    for (int i = 1; i <= codeDir.nSpecialSlots; i++) {
        uint8_t newHash[hashLen];
        uint32_t hashOffset = codeDir.hashOffset - (i * codeDir.hashSize);
        if (xmlEntitlements && i == CSSLOT_ENTITLEMENTS) {
            // XXX: memory_stream_get_raw_pointer only works for buffered streams
            hashFunc(memory_stream_get_raw_pointer(xmlEntitlements->stream), memory_stream_get_size(xmlEntitlements->stream), newHash);
            csd_blob_write(codeDirBlob, hashOffset, codeDir.hashSize, newHash);
        } else if (derEntitlements && i == CSSLOT_DER_ENTITLEMENTS) {
            hashFunc(memory_stream_get_raw_pointer(derEntitlements->stream), memory_stream_get_size(derEntitlements->stream), newHash);
            csd_blob_write(codeDirBlob, hashOffset, codeDir.hashSize, newHash);
        } else if (requirements && i == CSSLOT_REQUIREMENTS) {
            hashFunc(memory_stream_get_raw_pointer(requirements->stream), memory_stream_get_size(requirements->stream), newHash);
            csd_blob_write(codeDirBlob, hashOffset, codeDir.hashSize, newHash);
        }
    }

    return 0;
}

int csd_code_directory_update_code_slots(CS_DecodedBlob *codeDirBlob, MachO *macho)
{
    CS_CodeDirectory codeDir;
    csd_blob_read(codeDirBlob, 0, sizeof(CS_CodeDirectory), &codeDir);
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

    // since this function is only for updating the hashes
    // we make the assumption here that the nPages of the existing code directory is correct
    // TODO: maybe check that nCodeSlots lines up with what we expect
    
    for (uint32_t slotIdx = 0; slotIdx < codeDir.nCodeSlots; slotIdx++) {
        // Calculate hash
        uint8_t pageHash[codeDir.hashSize];
        if (!code_directory_calculate_page_hash(&codeDir, macho, slotIdx, pageHash)) {
            return -1;
        }

        // Write hash to CodeDirectory
        uint32_t offsetOfBlobToReplace = codeDir.hashOffset + (slotIdx * codeDir.hashSize);
        csd_blob_write(codeDirBlob, offsetOfBlobToReplace, codeDir.hashSize, pageHash);
    }

    return 0;
}

CS_DecodedBlob *csd_code_directory_init(MachO *macho, int hashType, bool alternate) {
    CS_CodeDirectory newCodeDir = { 0 };
    memset(&newCodeDir, 0, sizeof(CS_CodeDirectory));
    newCodeDir.magic = CSMAGIC_CODEDIRECTORY;
    newCodeDir.version = 0x20200;

    // Default values
    newCodeDir.nSpecialSlots = 7; // Only go down to DER entitlements hash
    newCodeDir.hashType = hashType;
    newCodeDir.hashSize = cs_hash_type_to_length(hashType);
    newCodeDir.pageSize = 0xC; // 0x4000
    newCodeDir.hashOffset = sizeof(CS_CodeDirectory) + (newCodeDir.nSpecialSlots * newCodeDir.hashSize);

    newCodeDir.nCodeSlots = (int)(align_to_size(memory_stream_get_size(macho->stream), 0x1000) / 0x1000);

    // Code limit
    // This is everything up to the FADE0CC0 magic

    CS_DecodedBlob *blob = malloc(sizeof(CS_DecodedBlob));
    blob->type = alternate ? CSSLOT_ALTERNATE_CODEDIRECTORIES : CSSLOT_CODEDIRECTORY;

    int finalLength = sizeof(CS_CodeDirectory) + (newCodeDir.nSpecialSlots * newCodeDir.hashSize) + (newCodeDir.nCodeSlots * newCodeDir.hashSize);
    newCodeDir.length = finalLength;
    CODE_DIRECTORY_APPLY_BYTE_ORDER(&newCodeDir, HOST_TO_BIG_APPLIER);
    void *buffer = malloc(finalLength);
    memset(buffer, 0, finalLength);
    memcpy(buffer, &newCodeDir, sizeof(CS_CodeDirectory));
    
    blob->stream = buffered_stream_init_from_buffer(buffer, finalLength, BUFFERED_STREAM_FLAG_AUTO_EXPAND);

    return blob;
}
