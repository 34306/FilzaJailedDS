#include "PatchFinder.h"
#include "MachO.h"
#include "MemoryStream.h"
#include "Util.h"
#include "PatchFinder_arm64.h"
#include <mach/machine.h>

void pfsec_info_populate_section(PFSectionInfo *sectionInfo, struct section_64 *section, MachOSegment *segment)
{
    sectionInfo->fileoff  = section->offset;
    sectionInfo->vmaddr   = section->addr;
    sectionInfo->size     = section->size;
    sectionInfo->initprot = segment->command.initprot;
    sectionInfo->maxprot  = segment->command.maxprot;

    strncpy(sectionInfo->segname, segment->command.segname, sizeof(segment->command.segname));
    sectionInfo->segname[sizeof(sectionInfo->segname)-1] = '\0';

    strncpy(sectionInfo->sectname, section->sectname, sizeof(section->sectname));
    sectionInfo->sectname[sizeof(sectionInfo->sectname)-1] = '\0';
}

void pfsec_info_populate_segment(PFSectionInfo *sectionInfo, MachOSegment *segment)
{
    sectionInfo->fileoff  = segment->command.fileoff;
    sectionInfo->vmaddr   = segment->command.vmaddr;
    sectionInfo->size     = segment->command.vmsize;
    sectionInfo->initprot = segment->command.initprot;
    sectionInfo->maxprot  = segment->command.maxprot;

    strncpy(sectionInfo->segname, segment->command.segname, sizeof(segment->command.segname));
    sectionInfo->segname[sizeof(sectionInfo->segname)-1] = '\0';

    sectionInfo->sectname[0] = '\0';
}

void pfsec_info_populate_dsc_mapping(PFSectionInfo *sectionInfo, DyldSharedCacheMapping *dscMapping)
{
    sectionInfo->fileoff  = dscMapping->fileoff;
    sectionInfo->vmaddr   = dscMapping->vmaddr;
    sectionInfo->size     = dscMapping->size;
    sectionInfo->initprot = dscMapping->initProt;
    sectionInfo->maxprot  = dscMapping->maxProt;

    char dscIdxStr[3];
    size_t filepathLen = strlen(dscMapping->file->filepath);
    if (dscMapping->file->filepath[filepathLen-3] == '.') {
        strncpy(dscIdxStr, &dscMapping->file->filepath[filepathLen-2], sizeof(dscIdxStr));
    }
    else {
        strncpy(dscIdxStr, "00", sizeof(dscIdxStr));
    }

    snprintf(sectionInfo->segname, sizeof(sectionInfo->segname), "__DSC_%s", dscIdxStr);

    if (dscMapping->flags & DYLD_CACHE_MAPPING_AUTH_DATA) {
        strlcpy(sectionInfo->sectname, "__auth_data", sizeof(sectionInfo->sectname));
    } else if (dscMapping->flags & DYLD_CACHE_MAPPING_DIRTY_DATA) {
        strlcpy(sectionInfo->sectname, "__data", sizeof(sectionInfo->sectname));
    } else if (dscMapping->flags & DYLD_CACHE_MAPPING_CONST_DATA) {
        strlcpy(sectionInfo->sectname, "__const_data", sizeof(sectionInfo->sectname));
    } else if (dscMapping->flags & DYLD_CACHE_MAPPING_TEXT_STUBS) {
        strlcpy(sectionInfo->sectname, "__text_stubs", sizeof(sectionInfo->sectname));
    } else if (dscMapping->flags & DYLD_CACHE_DYNAMIC_CONFIG_DATA) {
        strlcpy(sectionInfo->sectname, "__config_data", sizeof(sectionInfo->sectname));
    }
}

int raw_buffer_find_memory(uint8_t *buf, uint64_t searchStartOffset, uint64_t searchEndOffset, void *bytes, void *mask, size_t nbytes, uint16_t alignment, uint64_t *foundOffsetOut)
{
    __block int r = -1;
    enumerate_range(searchStartOffset, searchEndOffset, alignment, nbytes, ^bool(uint64_t cur) {
        if (!memcmp_masked(&buf[cur], bytes, mask, nbytes)) {
            *foundOffsetOut = cur;
            r = 0;
            return false;
        }
        return true;
    });
    return r;
}

PFSection *pfsec_init_from_macho(MachO *macho, const char *filesetEntryId, const char *segName, const char *sectName)
{
    PFSection *pfSection = NULL;
    MachO *machoToUse = NULL;
    if (filesetEntryId) {
        // try to find a fileset macho with this identifier
        for (uint32_t i = 0; i < macho->filesetCount; i++) {
            FilesetMachO *filesetMacho = &macho->filesetMachos[i];
            if (filesetMacho->underlyingMachO->slicesCount == 1) {
                if (!strcmp(filesetMacho->entry_id, filesetEntryId)) {
                    machoToUse = filesetMacho->underlyingMachO->slices[0];
                    break;
                }
            }
        }
    }
    else {
        machoToUse = macho;
    }

    if (machoToUse) {
        MachOSegment *segment = NULL;
        for (uint32_t i = 0; i < machoToUse->segmentCount; i++) {
            MachOSegment *segmentCandidate = machoToUse->segments[i];
            if (!strncmp(segmentCandidate->command.segname, segName, sizeof(segmentCandidate->command.segname))) {
                segment = segmentCandidate;
                break;
            }
        }
        if (segment) {
            if (sectName) {
                struct section_64 *section = NULL;
                for (uint32_t i = 0; i < segment->command.nsects; i++) {
                    struct section_64 *sectionCandidate = &segment->sections[i];	
                    if (!strncmp(sectionCandidate->sectname, sectName, sizeof(sectionCandidate->sectname))) {
                        section = sectionCandidate;
                    }
                }
                if (section) {
                    pfSection = malloc(sizeof(PFSection));
                    memset(pfSection, 0, sizeof(PFSection));
                    pfsec_info_populate_section(&pfSection->info, section, segment);
                }
            }
            else {
                pfSection = malloc(sizeof(PFSection));
                memset(pfSection, 0, sizeof(PFSection));
                pfsec_info_populate_segment(&pfSection->info, segment);
            }
        }
    }

    if (pfSection) {
        pfSection->cache = NULL;

        MemoryStream *stream = memory_stream_softclone(macho->stream);
        memory_stream_trim(stream, pfSection->info.fileoff, memory_stream_get_size(stream) - (pfSection->info.fileoff + pfSection->info.size));

        pfSection->stream = stream;
        pfSection->macho = macho;
    }

    return pfSection;
}

PFSection *pfsec_init_from_dsc_mapping(DyldSharedCache *sharedCache, DyldSharedCacheMapping *mapping)
{
    if (!sharedCache || !mapping) return NULL;

    PFSection *pfSection = malloc(sizeof(PFSection));
    if (!pfSection) return NULL;
    memset(pfSection, 0, sizeof(PFSection));

    pfsec_info_populate_dsc_mapping(&pfSection->info, mapping);

    pfSection->sharedCache = sharedCache;

    return pfSection;
}

MachO *pfsec_get_macho(PFSection *section)
{
    return section->macho;
}

DyldSharedCache *pfsec_get_dsc(PFSection *section)
{
    return section->sharedCache;
}

void pfsec_set_pointer_decoder(PFSection *section, uint64_t (*pointerDecoder)(struct s_PFSection *section, uint64_t vmaddr, uint64_t value))
{
    section->pointerDecoder = pointerDecoder;
}

int pfsec_read_reloff(PFSection *section, uint64_t rel, size_t size, void *outBuf)
{
    if (rel > section->info.size) return -1;

    void *rawPtr = pfsec_get_raw_pointer(section);
    if (rawPtr) {
        memcpy(outBuf, &rawPtr[rel], size);
        return 0;
    }
    else {
        // XXX: This does not work for MachOs that are inside the DSC
        // This code path will never be used for that however, since all DSC MachOs have a raw pointer
        return memory_stream_read(section->stream, rel, size, outBuf);
    }

    return -1;
}

uint32_t pfsec_read32_reloff(PFSection *section, uint64_t rel)
{
    uint32_t r = 0;
    pfsec_read_reloff(section, rel, sizeof(r), &r);
    return r;
}

int pfsec_read_string_reloff(PFSection *section, uint64_t rel, char **outString)
{
    if (rel > section->info.size) return -1;

    uint8_t *rawPtr = pfsec_get_raw_pointer(section);
    if (rawPtr) {
        const char *curString = (const char *)&rawPtr[rel];

        // make sure we don't end up reading OOB memory
        if ((uint8_t *)&curString[strnlen(curString, section->info.size - rel)] >= &rawPtr[section->info.size]) {
            return -1;
        }

        *outString = strdup(curString);
        return 0;
    }
    else if (section->stream) {
        // XXX: This does not work for MachOs that are inside the DSC
        // This code path will never be used for that however, since all DSC MachOs have a raw pointer
        return memory_stream_read_string(section->stream, rel, outString);
    }

    return -1;
}

int pfsec_read_string(PFSection *section, uint64_t vmaddr, char **outString)
{
    if (vmaddr < section->info.vmaddr) return -1;
    return pfsec_read_string_reloff(section, vmaddr - section->info.vmaddr, outString);
}

int pfsec_read_at_address(PFSection *section, uint64_t vmaddr, void *outBuf, size_t size)
{
    if (vmaddr < section->info.vmaddr) return -1;
    if (vmaddr + size > section->info.vmaddr + section->info.size) return -1;

    uint64_t rel = vmaddr - section->info.vmaddr;
    return pfsec_read_reloff(section, rel, size, outBuf);
}

uint32_t pfsec_read32(PFSection *section, uint64_t vmaddr)
{
    uint32_t r = 0;
    pfsec_read_at_address(section, vmaddr, &r, sizeof(r));
    return r;
}

uint64_t pfsec_read64(PFSection *section, uint64_t vmaddr)
{
    uint64_t r = 0;
    pfsec_read_at_address(section, vmaddr, &r, sizeof(r));
    return r;
}

uint64_t pfsec_read_pointer(PFSection *section, uint64_t vmaddr)
{
    uint64_t value = pfsec_read64(section, vmaddr);
    if (section->pointerDecoder) {
        return section->pointerDecoder(section, vmaddr, value);
    }
    return value;
}

int pfsec_set_cached(PFSection *section, bool cached)
{
    bool isCachedAlready = (bool)section->cache;
    if (cached != isCachedAlready && section->stream) {
        if (cached) {
            // If we already have a raw pointer, caching is obsolete
            if (pfsec_get_raw_pointer(section)) return 0;

            void *cache = malloc(section->info.size);
            int r = pfsec_read_reloff(section, 0, section->info.size, cache);
            if (r != 0) {
                free(cache);
                return r;
            }
            section->cache = cache;
        }
        else {
            free(section->cache);
            section->cache = NULL;
        }
    }
    return 0;
}

void *pfsec_get_raw_pointer(PFSection *section)
{
    DyldSharedCache *sharedCache = pfsec_get_dsc(section);
    if (!sharedCache) {
        MachO *macho = pfsec_get_macho(section);
        if (macho) {
            sharedCache = macho->containingCache;
        }
    }
    if (sharedCache) {
        return dsc_find_buffer(sharedCache, section->info.vmaddr, section->info.size);
    }

    uint8_t *rawPtr = NULL;
    if (section->stream) {
        rawPtr = memory_stream_get_raw_pointer(section->stream);
    }

    if (rawPtr) {
        return rawPtr;
    }
    else if(section->cache) {
        return section->cache;
    }
    return NULL;
}

int pfsec_find_memory_rel(PFSection *section, uint64_t searchStartOffset, uint64_t searchEndOffset, void *bytes, void *mask, size_t nbytes, uint16_t alignment, uint64_t *foundRelOffsetOut)
{
    void *rawPtr = pfsec_get_raw_pointer(section);
    if (rawPtr) {
        return raw_buffer_find_memory(rawPtr, searchStartOffset, searchEndOffset, bytes, mask, nbytes, alignment, foundRelOffsetOut);
    }
    else if (section->stream) {
        // XXX: This does not work for MachOs that are inside the DSC
        // This code path will never be used for that however, since all DSC MachOs have a raw pointer
        return memory_stream_find_memory(section->stream, searchStartOffset, searchEndOffset, bytes, mask, nbytes, alignment, foundRelOffsetOut);
    }

    return -1;
}

int pfsec_find_memory(PFSection *section, uint64_t searchStartAddr, uint64_t searchEndAddr, void *bytes, void *mask, size_t nbytes, uint16_t alignment, uint64_t *foundAddrOut)
{
    // Ensure searchStartAddr and searchEndAddr stay within section bounds
    if (searchStartAddr < section->info.vmaddr) searchStartAddr = section->info.vmaddr;
    if (searchEndAddr < section->info.vmaddr) searchEndAddr = section->info.vmaddr;
    if (searchStartAddr > (section->info.vmaddr + section->info.size)) searchStartAddr = section->info.vmaddr + section->info.size;
    if (searchEndAddr > (section->info.vmaddr + section->info.size)) searchEndAddr = section->info.vmaddr + section->info.size;

    uint64_t foundRelOff = 0;
    int r = pfsec_find_memory_rel(section, searchStartAddr - section->info.vmaddr, searchEndAddr - section->info.vmaddr, bytes, mask, nbytes, alignment, &foundRelOff);
    if (r == 0) {
        *foundAddrOut = section->info.vmaddr + foundRelOff;
    }

    return r;
}

// pfsec_find_prev_inst will start searching at the instruction *before* the instruction at startAddr
// + 0x1000: [first search comparison]
// + 0x1004: [startAddr]

uint64_t pfsec_find_prev_inst(PFSection *section, uint64_t startAddr, uint32_t searchCount, uint32_t inst, uint32_t mask)
{
    uint64_t out = 0;
    uint64_t endAddr = searchCount ? (startAddr - (sizeof(uint32_t) * searchCount)) : section->info.vmaddr;
    pfsec_find_memory(section, startAddr, endAddr, &inst, &mask, sizeof(inst), sizeof(uint32_t), &out);
    if (!out) return 0;
    return out;
}

// pfsec_find_next_inst will start searching at the instruction at startAddr
// + 0x1000: [startAddr, first search comparison]

uint64_t pfsec_find_next_inst(PFSection *section, uint64_t startAddr, uint32_t searchCount, uint32_t inst, uint32_t mask)
{
    uint64_t out = 0;
    uint64_t endAddr = searchCount ? (startAddr + (sizeof(uint32_t) * searchCount)) : (section->info.vmaddr + section->info.size);
    pfsec_find_memory(section, startAddr, endAddr, &inst, &mask, sizeof(inst), sizeof(uint32_t), &out);
    if (!out) return 0;
    return out;
}

uint64_t pfsec_find_function_start(PFSection *section, uint64_t midAddr)
{
    uint32_t cputype = 0;
    uint32_t cpusubtype = 0;

    MachO *macho = pfsec_get_macho(section);
    DyldSharedCache *sharedCache = pfsec_get_dsc(section);
    if (macho) {
        cputype = macho->machHeader.cputype;
        cpusubtype = macho->machHeader.cpusubtype;

        // If the MachO contains function starts, use those to determine the function start
        __block uint64_t start = 0;
        if (macho_enumerate_function_starts(macho, ^(uint64_t funcAddr, bool *stop){
            if (funcAddr <= midAddr) {
                start = funcAddr;
            }
            else {
                *stop = true;
            }
        }) == 0) {
            if (start >= section->info.vmaddr && start < (section->info.vmaddr + section->info.size)) {
                return start;
            }
        }
    }
    else if (sharedCache) {
        cputype = sharedCache->cputype;
        cpusubtype = sharedCache->cpusubtype;
    }

    // If there are no function starts, try to find them based on a heuristic approach
    if (cputype == CPU_TYPE_ARM64) {
        if ((cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) {
            // Find start of function by going back until we find a PACIBSP
            uint64_t addr = midAddr;
            while (addr > section->info.vmaddr && addr < (section->info.vmaddr + section->info.size)) {
                uint32_t curInst = pfsec_read32(section, addr);
                if (curInst == 0xd503237f) return addr;
                addr -= 4;
            }
        }
        else if ((cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64_ALL) {
            // Find start of function by going back until we find a stack frame push
            // Technique adapted from pongoOS
            uint64_t frameAddr = pfsec_find_prev_inst(section, midAddr, 0, 0x910003fd, 0xff8003ff); // add x29, sp, ?
            if (frameAddr) {
                uint64_t start = pfsec_find_prev_inst(section, frameAddr, 10, 0x29a003e0, 0x3be003e0); // stp ?, ?, [sp, ?]!
                if (!start) {
                    start = pfsec_find_prev_inst(section, frameAddr, 10, 0xd10003ff, 0xff8003ff); // sub sp, sp, ?
                }
                return start;
            }
        }
    }
    return 0;
}

bool pfsec_contains_vmaddr(PFSection *section, uint64_t addr)
{
    return (addr >= section->info.vmaddr && addr < (section->info.vmaddr + section->info.size));
}

void pfsec_free(PFSection *section)
{   
    if (section->stream) {
        memory_stream_free(section->stream);
    }
    pfsec_set_cached(section, false);
    free(section);
}

void _pfsec_run_pattern_metric(PFSection *section, uint64_t startAddr, uint64_t endAddr, PFPatternMetric *patternMetric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    uint16_t alignment = patternMetric->alignment;

    while (pfsec_find_memory(section, startAddr, endAddr, patternMetric->bytes, patternMetric->mask, patternMetric->nbytes, alignment, &startAddr) == 0) {
        bool stop = false;
        matchBlock(startAddr, &stop);
        if (stop) break;

        if (endAddr >= startAddr) {
            startAddr += alignment;
        }
        else {
            // When searching backwards, the search will automatically start one instruction before startAddr
            // Due to that, we do not need to decrement it by anything
        }
    }
}

PFPatternMetric *pfmetric_pattern_init(void *bytes, void *mask, size_t nbytes, uint16_t alignment)
{
    PFPatternMetric *metric = malloc(sizeof(PFPatternMetric));

    metric->shared.type = PFMETRIC_TYPE_PATTERN;
    metric->bytes = bytes;
    metric->mask = mask;
    metric->nbytes = nbytes;
    metric->alignment = alignment;

    return metric;
}

void _pfsec_run_string_metric(PFSection *section, uint64_t startAddr, uint64_t endAddr, PFStringMetric *stringMetric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    char *str = NULL;
    uint64_t searchOffset = 0;
    while (pfsec_read_string_reloff(section, searchOffset, &str) == 0) {
        if (!strcmp(str, stringMetric->string)) {
            bool stop = false;
            matchBlock(section->info.vmaddr + searchOffset, &stop);
            if (stop) break;
        }
        searchOffset += strlen(str)+1;
        free(str);
    }
}

PFStringMetric *pfmetric_string_init(const char *string)
{
    PFStringMetric *metric = malloc(sizeof(PFStringMetric));

    metric->shared.type = PFMETRIC_TYPE_STRING;
    metric->string = strdup(string);

    return metric;
}

void _pfsec_run_arm64_xref_metric(PFSection *section, uint64_t startAddr, uint64_t endAddr, PFXrefMetric *metric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    Arm64XrefTypeMask arm64Types = 0;
    if (metric->typeMask == 0) return;
    if (metric->typeMask & XREF_TYPE_MASK_CALL) {
        arm64Types |= ARM64_XREF_TYPE_MASK_CALL;
    }
    if (metric->typeMask & XREF_TYPE_MASK_JUMP) {
        arm64Types |= ARM64_XREF_TYPE_MASK_JUMP;
    }
    if (metric->typeMask & XREF_TYPE_MASK_REFERENCE) {
        arm64Types |= ARM64_XREF_TYPE_MASK_REFERENCE;
    }
    if (metric->typeMask & XREF_TYPE_MASK_POINTER) {
        arm64Types |= ARM64_XREF_TYPE_MASK_POINTER;
    }

    pfsec_arm64_enumerate_xrefs(section, arm64Types, ^(Arm64XrefType type, uint64_t source, uint64_t target, bool *stop) {
        bool match = false;
        if (metric->dynamicHandler) {
            match = metric->dynamicHandler(section, metric, source, target);
        }
        else {
            match = (target == metric->address);
        }

        if (match) {
            matchBlock(source, stop);
        }
    });
}

void _pfsec_run_xref_metric(PFSection *section, uint64_t startAddr, uint64_t endAddr, PFXrefMetric *xrefMetric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    uint32_t cputype = 0;
    MachO *macho = pfsec_get_macho(section);
    if (macho) {
        cputype = macho->machHeader.cputype;
    }
    else {
        DyldSharedCache *sharedCache = pfsec_get_dsc(section);
        if (sharedCache) {
            cputype = sharedCache->cputype;
        }
    }

    switch(cputype) {
        case CPU_TYPE_ARM64:
        _pfsec_run_arm64_xref_metric(section, startAddr, endAddr, xrefMetric, matchBlock);
        break;
    }
}

PFXrefMetric *pfmetric_xref_init(uint64_t address, PFXrefTypeMask types)
{
    PFXrefMetric *metric = malloc(sizeof(PFXrefMetric));
    if (!metric) return NULL;
    memset(metric, 0, sizeof(PFXrefMetric));

    metric->shared.type = PFMETRIC_TYPE_XREF;
    metric->address = address;
    metric->typeMask = types;

    return metric;
}

PFXrefMetric *pfmetric_dynamic_xref_init(bool (*dynamicHandler)(PFSection *section, PFXrefMetric *metric, uint64_t location, uint64_t target), void *ctx, PFXrefTypeMask types)
{
    PFXrefMetric *metric = malloc(sizeof(PFXrefMetric));
    if (!metric) return NULL;
    memset(metric, 0, sizeof(PFXrefMetric));

    metric->shared.type = PFMETRIC_TYPE_XREF;
    metric->dynamicHandler = dynamicHandler;
    metric->ctx = ctx;
    metric->typeMask = types;

    return metric;
}

void pfmetric_free(void *metric)
{
    uint32_t type = ((PFPatternMetric *)metric)->shared.type;
    if (type == PFMETRIC_TYPE_STRING) {
        free(((PFStringMetric *)metric)->string);
    }
    free(metric);
}

void pfmetric_run_in_range(PFSection *section, uint64_t startAddr, uint64_t endAddr, void *metric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    if (startAddr == -1ULL) startAddr = section->info.vmaddr;
    if (endAddr == -1ULL) endAddr = section->info.vmaddr + section->info.size;

    MetricShared *shared = metric;
    switch (shared->type) {
        case PFMETRIC_TYPE_PATTERN: {
            _pfsec_run_pattern_metric(section, startAddr, endAddr, metric, matchBlock);
            break;
        }
        case PFMETRIC_TYPE_STRING: {
            _pfsec_run_string_metric(section, startAddr, endAddr, metric, matchBlock);
            break;
        }
        case PFMETRIC_TYPE_XREF: {
            _pfsec_run_xref_metric(section, startAddr, endAddr, metric, matchBlock);
            break;
        }
    }
}

void pfmetric_run(PFSection *section, void *metric, void (^matchBlock)(uint64_t vmaddr, bool *stop))
{
    return pfmetric_run_in_range(section, -1, -1, metric, matchBlock);
}
