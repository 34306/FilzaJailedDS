#include "Fat.h"
#include "FileStream.h"
#include "MachO.h"
#include "MachOByteOrder.h"
#include "MachOLoadCommand.h"
#include "MemoryStream.h"

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/machine.h>
#include <stdlib.h>
#include <dlfcn.h>

int macho_read_at_offset(MachO *macho, uint64_t offset, size_t size, void *outBuf)
{
    if (macho->containingCache) {
        // When this MachO is inside the DSC, it will have segments that point to "out of macho" memory
        // So, attempt to translate every offset we get
        // Problem: Translation doesn't work before the segments have been loaded and loading the segments requires this function
        // Solution: Gracefully fall back to memory_stream_read in the case where translation fails
        uint64_t vmaddr = 0;
        if (macho_translate_fileoff_to_vmaddr(macho, offset, &vmaddr, NULL) == 0) {
            return macho_read_at_vmaddr(macho, vmaddr, size, outBuf);
        }
    }

    return memory_stream_read(macho->stream, offset, size, outBuf);
}

int macho_read_string_at_offset(MachO *macho, uint64_t offset, char **outString)
{
    if (macho->containingCache) {
        // Same as above
        uint64_t vmaddr = 0;
        if (macho_translate_fileoff_to_vmaddr(macho, offset, &vmaddr, NULL) == 0) {
            return macho_read_string_at_vmaddr(macho, vmaddr, outString);
        }
    }
    return memory_stream_read_string(macho->stream, offset, outString);
}

int macho_read_uleb128_at_offset(MachO *macho, uint64_t offset, uint64_t maxOffset, uint64_t *endOffsetOut, uint64_t *valueOut)
{
    uint64_t result = 0;
    int         bit = 0;
    
    uint64_t curOffset = offset;
    int r = 0;

    uint8_t v = 0;
    do {
        macho_read_at_offset(macho, curOffset, sizeof(v), &v);
        if (curOffset == maxOffset) {
            r = -1;
            break;
        }
        uint64_t slice = v & 0x7f;

        if (bit > 63) {
            r = -1;
            break;
        }
        else {
            result |= (slice << bit);
            bit += 7;
        }

        curOffset++;
    }
    while (v & 0x80);

    if (r == 0) {
        if (endOffsetOut) *endOffsetOut = curOffset;
        if (valueOut) *valueOut = result;
    }   

    return r;
}

int macho_write_at_offset(MachO *macho, uint64_t offset, size_t size, const void *inBuf)
{
    return memory_stream_write(macho->stream, offset, size, inBuf);
}

MemoryStream *macho_get_stream(MachO *macho)
{
    return macho->stream;
}

uint32_t macho_get_filetype(MachO *macho)
{
    return macho->machHeader.filetype;
}

struct mach_header *macho_get_mach_header(MachO *macho)
{
    return &macho->machHeader;
}

size_t macho_get_mach_header_size(MachO *macho)
{
    return macho->is32Bit ? sizeof(struct mach_header) : sizeof(struct mach_header_64);
}

DyldSharedCache *macho_get_containing_cache(MachO *macho)
{
    return macho->containingCache;
}

int macho_translate_fileoff_to_vmaddr(MachO *macho, uint64_t fileoff, uint64_t *vmaddrOut, MachOSegment **segmentOut)
{
    for (uint32_t i = 0; i < macho->segmentCount; i++) {
        MachOSegment *segment = macho->segments[i];
        uint64_t segmentStartOff = segment->command.fileoff;
        uint64_t segmentEndOff = segment->command.fileoff + segment->command.filesize;
        if (fileoff >= segmentStartOff && fileoff < segmentEndOff) {
            uint64_t relativeFileoff = fileoff - segmentStartOff;
            *vmaddrOut = segment->command.vmaddr + relativeFileoff;
            return 0;
        }
    }
    return -1;
}

int macho_translate_vmaddr_to_fileoff(MachO *macho, uint64_t vmaddr, uint64_t *fileoffOut, MachOSegment **segmentOut)
{
    for (uint32_t i = 0; i < macho->segmentCount; i++) {
        MachOSegment *segment = macho->segments[i];
        uint64_t segmentVmAddr = segment->command.vmaddr;
        uint64_t segmentVmEnd = segment->command.vmaddr + segment->command.vmsize;
        if (vmaddr >= segmentVmAddr && vmaddr < segmentVmEnd) {
            uint64_t relativeVmAddr = vmaddr - segmentVmAddr;
            *fileoffOut = segment->command.fileoff + relativeVmAddr;
            if (segmentOut) *segmentOut = segment;
            return 0;
        }
    }
    return -1;
}

int macho_read_at_vmaddr(MachO *macho, uint64_t vmaddr, size_t size, void *outBuf)
{
    if (macho->containingCache) {
        return dsc_read_from_vmaddr(macho->containingCache, vmaddr, size, outBuf);
    }
    else {
        MachOSegment *segment;
        uint64_t fileoff = 0;
        int r = macho_translate_vmaddr_to_fileoff(macho, vmaddr, &fileoff, &segment);
        if (r != 0) return r;

        uint64_t readEnd = vmaddr + size;
        if (readEnd >= (segment->command.vmaddr + segment->command.vmsize)) {
            // prevent OOB
            return -1;
        }

        return macho_read_at_offset(macho, fileoff, size, outBuf);
    }
}

int macho_read_string_at_vmaddr(MachO *macho, uint64_t vmaddr, char **outString)
{
    if (macho->containingCache) {
        return dsc_read_string_from_vmaddr(macho->containingCache, vmaddr, outString);
    }
    else {
        MachOSegment *segment;
        uint64_t fileoff = 0;
        int r = macho_translate_vmaddr_to_fileoff(macho, vmaddr, &fileoff, &segment);
        if (r != 0) return r;

        if (vmaddr >= (segment->command.vmaddr + segment->command.vmsize)) {
            // prevent OOB
            return -1;
        }

        return macho_read_string_at_offset(macho, fileoff, outString);
    }
}

int macho_write_at_vmaddr(MachO *macho, uint64_t vmaddr, size_t size, const void *inBuf)
{
    MachOSegment *segment;
    uint64_t fileoff = 0;
    int r = macho_translate_vmaddr_to_fileoff(macho, vmaddr, &fileoff, &segment);
    if (r != 0) return r;

    uint64_t readEnd = vmaddr + size;
    if (readEnd >= (segment->command.vmaddr + segment->command.vmsize)) {
        // prevent OOB
        return -1;
    }

    return macho_write_at_offset(macho, fileoff, size, inBuf);
}

int macho_enumerate_load_commands(MachO *macho, void (^enumeratorBlock)(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop))
{
    if (macho->machHeader.ncmds < 1 || macho->machHeader.ncmds > 1000) {
        printf("Error: invalid number of load commands (%d).\n", macho->machHeader.ncmds);
        return -1;
    }

    // First load command starts after mach header
    uint64_t offset = macho_get_mach_header_size(macho);

    for (int j = 0; j < macho->machHeader.ncmds; j++) {
        struct load_command loadCommand;
        if (macho_read_at_offset(macho, offset, sizeof(loadCommand), &loadCommand) != 0) continue;
        LOAD_COMMAND_APPLY_BYTE_ORDER(&loadCommand, LITTLE_TO_HOST_APPLIER);

        if (strcmp(load_command_to_string(loadCommand.cmd), "LC_UNKNOWN") == 0)
        {
            printf("Ignoring unknown command: 0x%x.\n", loadCommand.cmd);
        }
        else {
            // TODO: Check if cmdsize matches expected size for cmd
            uint8_t cmd[loadCommand.cmdsize];
            if (macho_read_at_offset(macho, offset, loadCommand.cmdsize, cmd) != 0) continue;
            bool stop = false;
            enumeratorBlock(loadCommand, offset, (void *)cmd, &stop);
            if (stop) break;
        }
        offset += loadCommand.cmdsize;
    }
    return 0;
}

int macho_enumerate_segments(MachO *macho, void (^enumeratorBlock)(struct segment_command_64 *segment, bool *stop))
{
    for (uint32_t i = 0; i < macho->segmentCount; i++) {
        bool stop = false;
        enumeratorBlock(&macho->segments[i]->command, &stop);
        if (stop) return 0;
    }
    return 0;
}

int macho_enumerate_sections(MachO *macho, void (^enumeratorBlock)(struct section_64 *section, struct segment_command_64 *segment, bool *stop))
{
    for (uint32_t i = 0; i < macho->segmentCount; i++) {
        for (uint32_t k = 0; k < macho->segments[i]->command.nsects; k++) {
            bool stop = false;
            enumeratorBlock(&macho->segments[i]->sections[k], &macho->segments[i]->command, &stop);
            if (stop) return 0;
        }
    }
    return 0;
}

struct trie_node {
    char *string;
    uint64_t value;
};

int macho_read_trie_node_at_offset(MachO *macho, uint64_t offset, uint64_t maxOffset, uint64_t *endOffsetOut, struct trie_node **trieNodesOut, unsigned *trieNodesCountOut)
{
    if (!trieNodesOut || !trieNodesCountOut) return -1;

    uint8_t trieValue = 0;
    macho_read_at_offset(macho, offset, sizeof(trieValue), &trieValue);
    offset += sizeof(trieValue);

    if (trieValue != 0) {
        *trieNodesOut = NULL;
        *trieNodesCountOut = 0;
        goto done;
    }

    uint8_t numberOfBranches = 0;
    macho_read_at_offset(macho, offset, sizeof(numberOfBranches), &numberOfBranches);
    offset += sizeof(numberOfBranches);

    *trieNodesCountOut = numberOfBranches;
    *trieNodesOut = malloc(sizeof(struct trie_node) * *trieNodesCountOut);

    for (uint8_t i = 0; i < numberOfBranches; i++) {
        struct trie_node *node = &(*trieNodesOut)[i];
        macho_read_string_at_offset(macho, offset, &node->string);
        offset += strlen(node->string)+1;
        macho_read_uleb128_at_offset(macho, offset, maxOffset, &offset, &node->value);
    }

done:
    if (endOffsetOut) *endOffsetOut = offset;
    return 0;
}

int macho_enumerate_symbols(MachO *macho, void (^enumeratorBlock)(const char *name, uint8_t type, uint64_t vmaddr, bool *stop))
{
    bool didScanDSC = false;

    if (macho->containingCache && macho->cacheImage) {
        // For stuff inside the DSC we need to use the cache image to also be able to fetch private symbols
        // Private symbols are normally replaced with <redacted> in the LC_SYMTAB of the MachO
        didScanDSC = (dsc_image_enumerate_symbols(macho->containingCache, macho->cacheImage, enumeratorBlock) == 0);
    }

    __block bool hasSymtab = false;
    __block struct symtab_command symtabCommand;
    __block bool hasExportsTrie = false;
    __block struct linkedit_data_command trieCommand;
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_SYMTAB) {
            hasSymtab = true;
            memcpy(&symtabCommand, cmd, sizeof(symtabCommand));
            SYMTAB_COMMAND_APPLY_BYTE_ORDER(&symtabCommand, LITTLE_TO_HOST_APPLIER);
        }
        else if (loadCommand.cmd == LC_DYLD_EXPORTS_TRIE) {
            hasExportsTrie = true;
            memcpy(&trieCommand, cmd, sizeof(trieCommand));
            LINKEDIT_DATA_COMMAND_APPLY_BYTE_ORDER(&trieCommand, LITTLE_TO_HOST_APPLIER);
        }

        if (hasSymtab && hasExportsTrie) *stop = true;
    });

    if (hasSymtab) {
        char *strtbl = malloc(symtabCommand.strsize);
        if (macho_read_at_offset(macho, symtabCommand.stroff, symtabCommand.strsize, strtbl) != 0) {
            free(strtbl);
            return -1;
        }

        for (int i = 0; i < symtabCommand.nsyms; i++) {
            uint64_t n_strx = 0;
            uint64_t n_value = 0;
            uint8_t n_type = 0;
            int r = 0;

            #define _GENERIC_READ_NLIST(nlistType, APPLIER) do { \
                struct nlistType entry; \
                if ((r = macho_read_at_offset(macho, symtabCommand.symoff + (i * sizeof(entry)), sizeof(entry), &entry)) != 0) break; \
                APPLIER(&entry, LITTLE_TO_HOST_APPLIER); \
                n_strx = entry.n_un.n_strx; \
                n_value = entry.n_value; \
                n_type = entry.n_type; \
            } while (0)

            if (macho->is32Bit) {
                _GENERIC_READ_NLIST(nlist, NLIST_APPLY_BYTE_ORDER);
            }
            else {
                _GENERIC_READ_NLIST(nlist_64, NLIST_64_APPLY_BYTE_ORDER);
            }

            if (r != 0) continue;

            #undef _GENERIC_READ_NLIST

            if (n_strx >= symtabCommand.strsize || n_strx == 0) continue;

            const char *symbolName = &strtbl[n_strx];
            if (symbolName[0] == 0) continue;

            if (didScanDSC) {
                /* If we already got the real private symbols from the DSC, omit any censored ones */
                if (!strcmp(symbolName, "<redacted>")) continue;
            }

            bool stopSym = false;
            enumeratorBlock(symbolName, n_type, n_value, &stopSym);
            if (stopSym) {
                break;
            }
        }
        free(strtbl);
    }
    else if (hasExportsTrie) {
        uint64_t trieBegin = trieCommand.dataoff;
        uint64_t trieSize = trieCommand.datasize;
        uint64_t trieEnd = trieBegin + trieSize;

        uint64_t trieBeginVm = 0;
        uint64_t trieEndVm = 0;
        macho_translate_fileoff_to_vmaddr(macho, trieBegin, &trieBeginVm, NULL);
        macho_translate_fileoff_to_vmaddr(macho, trieEnd, &trieEndVm, NULL);

        uint64_t trieCur = trieBegin;

        struct trie_node *frontier = NULL;
        unsigned frontierCount = 0;
        macho_read_trie_node_at_offset(macho, trieCur, trieEnd, &trieCur, &frontier, &frontierCount);
        for (unsigned i = 0; i < frontierCount; i++) {
            struct trie_node *node = &frontier[i];
            
            uint64_t offset = trieBegin + node->value;
            struct trie_node *children = NULL;
            unsigned childrenCount = 0;
            macho_read_trie_node_at_offset(macho, offset, trieEnd, &offset, &children, &childrenCount);
            if (!childrenCount) {
                uint64_t ulebOffset = offset - sizeof(uint8_t);
                uint64_t flags = 0;
                macho_read_uleb128_at_offset(macho, ulebOffset, trieEnd, &ulebOffset, &flags);
                ulebOffset += sizeof(uint8_t);

                uint64_t addrOff = 0;
                macho_read_uleb128_at_offset(macho, ulebOffset, trieEnd, &ulebOffset, &addrOff);
                
                bool stop = false;
                enumeratorBlock(node->string, 0, macho_get_base_address(macho) + addrOff, &stop);
                if (stop) break;
            }
            else {
                unsigned prevEnd = frontierCount;
                frontierCount += childrenCount;
                frontier = realloc(frontier, sizeof(struct trie_node) * frontierCount);
                node = &frontier[i];

                for (unsigned k = 0; k < childrenCount; k++) {
                    frontier[prevEnd + k].string = malloc(strlen(node->string) + strlen(children[k].string) + 1);
                    strcpy(frontier[prevEnd + k].string, node->string);
                    strcat(frontier[prevEnd + k].string, children[k].string);
                    frontier[prevEnd + k].value = children[k].value;
                }

                for (unsigned k = 0; k < childrenCount; k++) {
                    free(children[k].string);
                }
                free(children);
            }
        }

        for (unsigned i = 0; i < frontierCount; i++) {
            free(frontier[i].string);
        }
        free(frontier);
    }

    return 0;
}

int macho_enumerate_dependencies(MachO *macho, void (^enumeratorBlock)(const char *dylibPath, uint32_t cmd, struct dylib* dylib, bool *stop))
{
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop){
        if (loadCommand.cmd == LC_LOAD_DYLIB || 
            loadCommand.cmd == LC_LOAD_WEAK_DYLIB || 
            loadCommand.cmd == LC_REEXPORT_DYLIB || 
            loadCommand.cmd == LC_LAZY_LOAD_DYLIB ||
            loadCommand.cmd == LC_LOAD_UPWARD_DYLIB) {
            struct dylib_command *dylibCommand = (struct dylib_command *)cmd;
            DYLIB_COMMAND_APPLY_BYTE_ORDER(dylibCommand, LITTLE_TO_HOST_APPLIER);
            if (dylibCommand->dylib.name.offset >= loadCommand.cmdsize || dylibCommand->dylib.name.offset < sizeof(struct dylib_command)) {
                printf("WARNING: Malformed dependency at 0x%llx (Name offset out of bounds)\n", offset);
                return;
            }
            char *dependencyPath = ((char *)cmd + dylibCommand->dylib.name.offset);
            size_t dependencyLength = strnlen(dependencyPath, loadCommand.cmdsize - dylibCommand->dylib.name.offset);
            if (!dependencyLength) {
                printf("WARNING: Malformed dependency at 0x%llx (Name has zero length)\n", offset);
                return;
            }
            if (dependencyPath[dependencyLength] != 0) {
                printf("WARNING: Malformed dependency at 0x%llx (Name has non NULL end byte)\n", offset);
                return;
            }

            bool stopDepdendency = false;
            enumeratorBlock(dependencyPath, loadCommand.cmd, &dylibCommand->dylib, &stopDepdendency);
            if (stopDepdendency) {
                *stop = true;
                return;
            }
        }
    });
    return 0;
}

int macho_enumerate_rpaths(MachO *macho, void (^enumeratorBlock)(const char *rpath, bool *stop))
{
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_RPATH) {
            struct rpath_command *rpathCommand = (struct rpath_command *)cmd;
            RPATH_COMMAND_APPLY_BYTE_ORDER(rpathCommand, LITTLE_TO_HOST_APPLIER);

            if (rpathCommand->path.offset >= loadCommand.cmdsize || rpathCommand->path.offset < sizeof(struct rpath_command)) {
                printf("WARNING: Malformed rpath at 0x%llx (Path offset out of bounds)\n", offset);
                return;
            }

            char *rpath = ((char *)cmd) + rpathCommand->path.offset;
            size_t rpathLength = strnlen(rpath, rpathCommand->cmdsize - rpathCommand->path.offset);
            if (!rpathLength) {
                printf("WARNING: Malformed rpath at 0x%llx (Path has zero length)\n", offset);
                return;
            }
            if (rpath[rpathLength] != 0) {
                printf("WARNING: Malformed rpath at 0x%llx (Name has non NULL end byte)\n", offset);
                return;
            }

            bool stopRpath = false;
            enumeratorBlock(rpath, &stopRpath);
            if (stopRpath) {
                *stop = true;
            }
        }
    });
    return 0;
}

uint64_t macho_get_base_address(MachO *macho)
{
    if (macho->cachedBase) return macho->cachedBase;
    __block int64_t base = UINT64_MAX;
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_SEGMENT_64) {
            struct segment_command_64 *segmentCommand = (struct segment_command_64 *)cmd;
            SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(segmentCommand, LITTLE_TO_HOST_APPLIER);
            if (strncmp(segmentCommand->segname, "__PRELINK", 9) != 0 
                && strncmp(segmentCommand->segname, "__PLK", 5) != 0
                && strncmp(segmentCommand->segname, "__PAGEZERO", 10) != 0) {
                // PRELINK and PAGEZERO are before the actual base, so we ignore them
                if (segmentCommand->vmaddr < base) {
                    base = segmentCommand->vmaddr;
                }
            }
        }
    });
    macho->cachedBase = base;
    return macho->cachedBase;
}

int macho_enumerate_function_starts(MachO *macho, void (^enumeratorBlock)(uint64_t funcAddr, bool *stop))
{
    __block uint64_t functionStartsDataOff = 0, functionStartsDataSize = 0;

    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stopLC) {
        if (loadCommand.cmd == LC_FUNCTION_STARTS) {
            struct linkedit_data_command *functionStartsCommand = (struct linkedit_data_command *)cmd;
            LINKEDIT_DATA_COMMAND_APPLY_BYTE_ORDER(functionStartsCommand, LITTLE_TO_HOST_APPLIER);
            functionStartsDataOff = functionStartsCommand->dataoff;
            functionStartsDataSize = functionStartsCommand->datasize;
            *stopLC = true;
        }
    });

    if (!functionStartsDataOff || !functionStartsDataSize) return -1;

    uint8_t *info = malloc(functionStartsDataSize);
    if (macho_read_at_offset(macho, functionStartsDataOff, functionStartsDataSize, info) == 0) {
        uint8_t *infoEnd = &info[functionStartsDataSize];
        uint64_t address = macho_get_base_address(macho);
        for (uint8_t *p = info; (*p != 0) && (p < infoEnd); ) {
            bool stop = false;
            uint64_t delta = 0;
            uint32_t shift = 0;
            bool more = true;
            do {
                uint8_t byte = *p++;
                delta |= ((byte & 0x7F) << shift);
                shift += 7;
                if (byte < 0x80) {
                    address += delta;
                    enumeratorBlock(address, &stop);
                    more = false;
                }
            } while (more);
            if (stop) break;
        }
    }
    free(info);

    return 0;
}

int macho_lookup_segment_by_addr(MachO *macho, uint64_t vmaddr, struct segment_command_64 *segmentOut)
{
    __block int r = -1;
    macho_enumerate_segments(macho, ^(struct segment_command_64 *segment, bool *stop){
        if (vmaddr >= segment->vmaddr && vmaddr < (segment->vmaddr + segment->vmsize)) {
            r = 0;
            memcpy(segmentOut, segment, sizeof(struct segment_command_64));
            *stop = true;
        }
    });
    return r;
}

int macho_lookup_section_by_addr(MachO *macho, uint64_t vmaddr, struct section_64 *sectionOut)
{
    __block int r = -1;
    macho_enumerate_sections(macho, ^(struct section_64 *section, struct segment_command_64 *segment, bool *stop) {
        if (vmaddr >= section->addr && vmaddr < (section->addr + section->size)) {
            r = 0;
            memcpy(sectionOut, section, sizeof(struct section_64));
            *stop = true;
        }
    });
    return r;
}

int macho_parse_segments(MachO *macho)
{
    return macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        if (macho->is32Bit && loadCommand.cmd == LC_SEGMENT) {
            macho->segmentCount++;
            if (macho->segments == NULL) { macho->segments = malloc(macho->segmentCount * sizeof(MachOSegment*)); }
            else { macho->segments = realloc(macho->segments, macho->segmentCount * sizeof(MachOSegment*)); }
            
            // For simplicity, we convert segment_command's to segment_command_64's
            // This allowes all logic to unifily operate on segment_command_64

            struct segment_command segmentCommand;
            memcpy(&segmentCommand, cmd, sizeof(segmentCommand));
            SEGMENT_COMMAND_APPLY_BYTE_ORDER(&segmentCommand, LITTLE_TO_HOST_APPLIER);
            
            MachOSegment **segment = &macho->segments[macho->segmentCount-1];
            
            *segment = malloc(sizeof(MachOSegment) + segmentCommand.nsects * sizeof(struct section_64));
            (*segment)->command = (struct segment_command_64) {
                .cmd = segmentCommand.cmd,
                .cmdsize = segmentCommand.cmdsize,
                .fileoff = segmentCommand.fileoff,
                .filesize = segmentCommand.filesize,
                .vmaddr = segmentCommand.vmaddr,
                .vmsize = segmentCommand.vmsize,
                .flags = segmentCommand.flags,
                .initprot = segmentCommand.initprot,
                .maxprot = segmentCommand.maxprot,
                .nsects = segmentCommand.nsects,
            };
            memcpy((*segment)->command.segname, segmentCommand.segname, sizeof(segmentCommand.segname));
            
            for (uint32_t i = 0; i < macho->segments[macho->segmentCount-1]->command.nsects; i++) {
                struct section section;
                memcpy(&section, cmd + sizeof(struct segment_command) + (i * sizeof(struct section)), sizeof(section));
                SECTION_APPLY_BYTE_ORDER(&section, LITTLE_TO_HOST_APPLIER);
                
                (*segment)->sections[i] = (struct section_64) {
                    .addr = section.addr,
                    .align = section.align,
                    .flags = section.flags,
                    .nreloc = section.nreloc,
                    .offset = section.offset,
                    .reserved1 = section.reserved1,
                    .reserved2 = section.reserved2,
                    .reserved3 = 0,
                    .size = section.size,
                };
                
                memcpy((*segment)->sections[i].sectname, section.sectname, sizeof(section.sectname));
                memcpy((*segment)->sections[i].segname, section.segname, sizeof(section.segname));
            }
        }
        else if (!macho->is32Bit && loadCommand.cmd == LC_SEGMENT_64) {
            macho->segmentCount++;
            if (macho->segments == NULL) { macho->segments = malloc(macho->segmentCount * sizeof(MachOSegment*)); }
            else { macho->segments = realloc(macho->segments, macho->segmentCount * sizeof(MachOSegment*)); }
            macho->segments[macho->segmentCount-1] = malloc(loadCommand.cmdsize);
            memcpy(macho->segments[macho->segmentCount-1], cmd, loadCommand.cmdsize);
            SEGMENT_COMMAND_64_APPLY_BYTE_ORDER(&macho->segments[macho->segmentCount-1]->command, LITTLE_TO_HOST_APPLIER);
            for (uint32_t i = 0; i < macho->segments[macho->segmentCount-1]->command.nsects; i++) {
                SECTION_64_APPLY_BYTE_ORDER(&macho->segments[macho->segmentCount-1]->sections[i], LITTLE_TO_HOST_APPLIER);
            }
        }
    });
}

int macho_parse_fileset_machos(MachO *macho)
{
    if (macho_get_filetype(macho) != MH_FILESET) return -1;
    return macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_FILESET_ENTRY) {
            uint32_t i = macho->filesetCount;
            macho->filesetCount++;

            struct fileset_entry_command *filesetCommand = cmd;
            FILESET_ENTRY_COMMAND_APPLY_BYTE_ORDER(filesetCommand, LITTLE_TO_HOST_APPLIER);

            if (macho->filesetMachos == NULL) { macho->filesetMachos = malloc(macho->filesetCount * sizeof(FilesetMachO)); }
            else { macho->filesetMachos = realloc(macho->filesetMachos, macho->filesetCount * sizeof(FilesetMachO)); }

            FilesetMachO *filesetMacho = &macho->filesetMachos[i];
            filesetMacho->entry_id = strdup((char *)cmd + filesetCommand->entry_id.offset);
            filesetMacho->vmaddr = filesetCommand->vmaddr;
            filesetMacho->fileoff = filesetCommand->fileoff;
            
            MemoryStream *subStream = memory_stream_softclone(macho->stream);
            
            // TODO: Also cut trim to the end of the macho, but for that we would need to determine it's size
            memory_stream_trim(subStream, filesetCommand->fileoff, 0);
            filesetMacho->underlyingMachO = fat_init_from_memory_stream(subStream);
        }
    });
}

int _macho_parse(MachO *macho)
{
    macho->is32Bit = (macho->archDescriptor.cpusubtype == CPU_SUBTYPE_ARM_V6 || macho->archDescriptor.cpusubtype == CPU_SUBTYPE_ARM_V7 || macho->archDescriptor.cpusubtype == CPU_SUBTYPE_ARM_V7S);
    if (macho->machHeader.sizeofcmds % (macho->is32Bit ? sizeof(uint32_t) : sizeof(uint64_t)) != 0) {
        printf("Error: sizeofcmds is not a multiple of %lu (%d).\n", macho->is32Bit ? sizeof(uint32_t) : sizeof(uint64_t), macho->machHeader.sizeofcmds);
        return -1;
    }
    macho_parse_segments(macho);
    macho_parse_fileset_machos(macho);
    return 0;
}

MachO *macho_init(MemoryStream *stream, struct fat_arch_64 archDescriptor)
{
    MachO *macho = malloc(sizeof(MachO));
    if (!macho) return NULL;
    memset(macho, 0, sizeof(MachO));

    macho->stream = stream;
    macho->archDescriptor = archDescriptor;
    if (macho_read_at_offset(macho, 0, sizeof(macho->machHeader), &macho->machHeader) != 0) goto fail;
    MACH_HEADER_APPLY_BYTE_ORDER(&macho->machHeader, LITTLE_TO_HOST_APPLIER);

    // Check the magic against the expected values
    if (macho->machHeader.magic != MH_MAGIC_64 && macho->machHeader.magic != MH_MAGIC) {
        goto fail;
    }

    if (_macho_parse(macho) != 0) goto fail;

    return macho;

fail:
    macho_free(macho);
    return NULL;
}

MachO *macho_init_for_writing(const char *filePath)
{
    MachO *macho = malloc(sizeof(MachO));
    if (!macho) return NULL;
    memset(macho, 0, sizeof(MachO));

    macho->stream = file_stream_init_from_path(filePath, 0, FILE_STREAM_SIZE_AUTO, FILE_STREAM_FLAG_WRITABLE | FILE_STREAM_FLAG_AUTO_EXPAND);
    if (!macho->stream) goto fail;

    size_t fileSize = memory_stream_get_size(macho->stream);
    memory_stream_read(macho->stream, 0, sizeof(struct mach_header), &macho->machHeader);
    MACH_HEADER_APPLY_BYTE_ORDER(&macho->machHeader, HOST_TO_LITTLE_APPLIER);
    if (macho->machHeader.magic != MH_MAGIC_64) goto fail;

    macho->archDescriptor.cpusubtype = macho->machHeader.cpusubtype;
    macho->archDescriptor.cputype = macho->machHeader.cputype;
    macho->archDescriptor.offset = 0;
    macho->archDescriptor.size = fileSize;
    macho->archDescriptor.align = 0x4000;

    if (_macho_parse(macho) != 0) goto fail;

    return macho;

fail:
    macho_free(macho);
    return NULL;
}

MachO **macho_array_create_for_paths(char **inputPaths, int inputPathsCount) {
    Fat **fatArray = malloc(sizeof(Fat *) * inputPathsCount);
    MachO **machoArray;
    int sliceCount = 0;
    for (int i = 0; i < inputPathsCount; i++) {
        Fat *fat = fat_init_from_path(inputPaths[i]);
        if (!fat) {
            printf("Error: failed to create Fat from file: %s\n", inputPaths[i]);
            return NULL;
        }
        sliceCount += fat->slicesCount;
        fatArray[i] = fat;
    }
    machoArray = malloc(sizeof(MachO *) * sliceCount);
    for (int i = 0; i < inputPathsCount; i++) {
        for (int j = 0; j < fatArray[i]->slicesCount; j++) {
            machoArray[i] = fatArray[i]->slices[j];
        }
    }
    return machoArray;
}

bool macho_is_encrypted(MachO *macho)
{
    __block bool isEncrypted = false;
    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
        if (loadCommand.cmd == LC_ENCRYPTION_INFO_64 || loadCommand.cmd == LC_ENCRYPTION_INFO) {
            struct encryption_info_command *encryptionInfoCommand = cmd;
            ENCRYPTION_INFO_COMMAND_APPLY_BYTE_ORDER(encryptionInfoCommand, LITTLE_TO_HOST_APPLIER);
            if (encryptionInfoCommand->cryptid == 1) {
                *stop = true;
                isEncrypted = true;
            }
        }
    });
    return isEncrypted;
}

void macho_free(MachO *macho)
{
    if (macho->filesetCount != 0 && macho->filesetMachos) {
        for (uint32_t i = 0; i < macho->filesetCount; i++) {
            fat_free(macho->filesetMachos[i].underlyingMachO);
            free(macho->filesetMachos[i].entry_id);
        }
        free(macho->filesetMachos);
    }
    if (macho->segmentCount != 0 && macho->segments) {
        for (uint32_t i = 0; i < macho->segmentCount; i++) {
            free(macho->segments[i]);
        }
        free(macho->segments);
    }
    if (macho->stream) {
        memory_stream_free(macho->stream);
    }
    free(macho);
}
