#include "MachOLoadCommand.h"
#include "Util.h"
#include "CSBlob.h"

char *load_command_to_string(int loadCommand) {
    switch (loadCommand) {
        case LC_SEGMENT:
            return "LC_SEGMENT";
        case LC_SYMTAB:
            return "LC_SYMTAB";
        case LC_SYMSEG:
            return "LC_SYMSEG";
        case LC_THREAD:
            return "LC_THREAD";
        case LC_UNIXTHREAD:
            return "LC_UNIXTHREAD";
        case LC_LOADFVMLIB:
            return "LC_LOADFVMLIB";
        case LC_IDFVMLIB:
            return "LC_IDFVMLIB";
        case LC_IDENT:
            return "LC_IDENT";
        case LC_FVMFILE:
            return "LC_FVMFILE";
        case LC_PREPAGE:
            return "LC_PREPAGE";
        case LC_DYSYMTAB:
            return "LC_DYSYMTAB";
        case LC_LOAD_DYLIB:
            return "LC_LOAD_DYLIB";
        case LC_ID_DYLIB:
            return "LC_ID_DYLIB";
        case LC_LOAD_DYLINKER:
            return "LC_LOAD_DYLINKER";
        case LC_ID_DYLINKER:
            return "LC_ID_DYLINKER";
        case LC_PREBOUND_DYLIB:
            return "LC_PREBOUND_DYLIB";
        case LC_ROUTINES:
            return "LC_ROUTINES";
        case LC_SUB_FRAMEWORK:
            return "LC_SUB_FRAMEWORK";
        case LC_SUB_UMBRELLA:
            return "LC_SUB_UMBRELLA";
        case LC_SUB_CLIENT:
            return "LC_SUB_CLIENT";
        case LC_SUB_LIBRARY:
            return "LC_SUB_LIBRARY";
        case LC_TWOLEVEL_HINTS:
            return "LC_TWOLEVEL_HINTS";
        case LC_PREBIND_CKSUM:
            return "LC_PREBIND_CKSUM";
        case LC_LOAD_WEAK_DYLIB:
            return "LC_LOAD_WEAK_DYLIB";
        case LC_SEGMENT_64:
            return "LC_SEGMENT_64";
        case LC_ROUTINES_64:
            return "LC_ROUTINES_64";
        case LC_UUID:
            return "LC_UUID";
        case LC_RPATH:
            return "LC_RPATH";
        case LC_CODE_SIGNATURE:
            return "LC_CODE_SIGNATURE";
        case LC_SEGMENT_SPLIT_INFO:
            return "LC_SEGMENT_SPLIT_INFO";
        case LC_REEXPORT_DYLIB:
            return "LC_REEXPORT_DYLIB";
        case LC_LAZY_LOAD_DYLIB:
            return "LC_LAZY_LOAD_DYLIB";
        case LC_ENCRYPTION_INFO:
            return "LC_ENCRYPTION_INFO";
        case LC_DYLD_INFO:
            return "LC_DYLD_INFO";
        case LC_DYLD_INFO_ONLY:
            return "LC_DYLD_INFO_ONLY";
        case LC_LOAD_UPWARD_DYLIB:
            return "LC_LOAD_UPWARD_DYLIB";
        case LC_VERSION_MIN_MACOSX:
            return "LC_VERSION_MIN_MACOSX";
        case LC_VERSION_MIN_IPHONEOS:
            return "LC_VERSION_MIN_IPHONEOS";
        case LC_FUNCTION_STARTS:
            return "LC_FUNCTION_STARTS";
        case LC_DYLD_ENVIRONMENT:
            return "LC_DYLD_ENVIRONMENT";
        case LC_MAIN:
            return "LC_MAIN";
        case LC_DATA_IN_CODE:
            return "LC_DATA_IN_CODE";
        case LC_SOURCE_VERSION:
            return "LC_SOURCE_VERSION";
        case LC_DYLIB_CODE_SIGN_DRS:
            return "LC_DYLIB_CODE_SIGN_DRS";
        case LC_ENCRYPTION_INFO_64:
            return "LC_ENCRYPTION_INFO_64";
        case LC_LINKER_OPTION:
            return "LC_LINKER_OPTION";
        case LC_LINKER_OPTIMIZATION_HINT:
            return "LC_LINKER_OPTIMIZATION_HINT";
        case LC_VERSION_MIN_TVOS:
            return "LC_VERSION_MIN_TVOS";
        case LC_VERSION_MIN_WATCHOS:
            return "LC_VERSION_MIN_WATCHOS";
        case LC_NOTE:
            return "LC_NOTE";
        case LC_BUILD_VERSION:
            return "LC_BUILD_VERSION";
        case LC_DYLD_EXPORTS_TRIE:
            return "LC_DYLD_EXPORTS_TRIE";
        case LC_DYLD_CHAINED_FIXUPS:
            return "LC_DYLD_CHAINED_FIXUPS";
        case LC_FILESET_ENTRY:
            return "LC_FILESET_ENTRY";
        default:
            return "LC_UNKNOWN";
    }
}

void update_segment_command_64(MachO *macho, const char *segmentName, uint64_t vmaddr, uint64_t vmsize, uint64_t fileoff, uint64_t filesize) {
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_SEGMENT_64) {
            struct segment_command_64 *segmentCommand = (struct segment_command_64 *)cmd;
            SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(segmentCommand, LITTLE_TO_HOST_APPLIER);
            if (strcmp(segmentCommand->segname, segmentName) == 0) {
                segmentCommand->vmaddr = vmaddr;
                segmentCommand->vmsize = vmsize;
                segmentCommand->fileoff = fileoff;
                segmentCommand->filesize = filesize;
                SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(segmentCommand, HOST_TO_LITTLE_APPLIER);
                memory_stream_write(macho->stream, offset, sizeof(struct segment_command_64), segmentCommand);
                *stop = true;
            }
        }
    });
}

void update_lc_code_signature(MachO *macho, uint64_t size) {
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command *csLoadCommand = (struct linkedit_data_command *)cmd;
            LINKEDIT_DATA_COMMAND_APPLY_BYTE_ORDER(csLoadCommand, LITTLE_TO_HOST_APPLIER);
            csLoadCommand->datasize = size;
            LINKEDIT_DATA_COMMAND_APPLY_BYTE_ORDER(csLoadCommand, HOST_TO_LITTLE_APPLIER);
            memory_stream_write(macho->stream, offset, sizeof(struct linkedit_data_command), csLoadCommand);
            *stop = true;
        }
    });
}

int update_load_commands_for_coretrust_bypass(MachO *macho, CS_SuperBlob *superblob, uint64_t originalCodeSignatureSize) {

    uint64_t sizeOfCodeSignature = BIG_TO_HOST(superblob->length);

    // Calculate how much padding we currently have
    __block uint64_t blockPaddingSize = 0;
    __block uint64_t vmAddress = 0;
    __block uint64_t fileOffset = 0;
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_SEGMENT_64) {
            struct segment_command_64 *segmentCommand = (struct segment_command_64 *)cmd;
            SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(segmentCommand, LITTLE_TO_HOST_APPLIER);
            if (strcmp(segmentCommand->segname, "__LINKEDIT") == 0) {
                blockPaddingSize = segmentCommand->filesize - originalCodeSignatureSize;
                vmAddress = segmentCommand->vmaddr;
                fileOffset = segmentCommand->fileoff;
                *stop = true;
            }
        }
    });

    if (blockPaddingSize == 0 || vmAddress == 0 || fileOffset == 0) {
        printf("Error: failed to get existing values for __LINKEDIT segment.\n");
        return -1;
    }

    uint64_t newSegmentSize = sizeOfCodeSignature + blockPaddingSize;
    uint64_t newVMSize = align_to_size(newSegmentSize, 0x4000);

    // Update the segment command
    printf("Updating __LINKEDIT segment...\n");
    update_segment_command_64(macho, "__LINKEDIT", vmAddress, newVMSize, fileOffset, newSegmentSize);

    // Update the code signature load command
    printf("Updating LC_CODE_SIGNATURE load command...\n");
    update_lc_code_signature(macho, sizeOfCodeSignature);

    return 0;
}