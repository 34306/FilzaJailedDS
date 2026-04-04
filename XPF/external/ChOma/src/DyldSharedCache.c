#include "DyldSharedCache.h"
#include <libgen.h>
#include <sys/syslimits.h>
#include <sys/types.h>
#include <mach-o/nlist.h>
#include <dirent.h>
#include <sys/mman.h>
#include "BufferedStream.h"
#include "Util.h"
#include "MachO.h"
#include "Fat.h"

int string_comparator(void const *a, void const *b) { 
    char const *aa = *(char const **)a;
    char const *bb = *(char const **)b;

    int r = strcmp(aa, bb);
    return r;
}

void dsc_enumerate_mappings(DyldSharedCache *sharedCache, void (^enumeratorBlock)(DyldSharedCacheMapping *mapping, DyldSharedCacheFile *sourceFile, bool *stop))
{
    for (unsigned i = 0; i < sharedCache->mappingCount; i++) {
        DyldSharedCacheMapping *mapping = &sharedCache->mappings[i];
        bool stop = false;
        enumeratorBlock(mapping, mapping->file, &stop);
        if (stop) break;
    }
}

DyldSharedCacheMapping *dsc_lookup_mapping(DyldSharedCache *sharedCache, uint64_t vmaddr, uint64_t size)
{
    __block DyldSharedCacheMapping *mappingOut = NULL;

    dsc_enumerate_mappings(sharedCache, ^(DyldSharedCacheMapping *mapping, DyldSharedCacheFile *sourceFile, bool *stop) {
        uint64_t mappingEndAddr = mapping->vmaddr + mapping->size;
        uint64_t searchEndAddr = vmaddr + size;
        if (size != 0) searchEndAddr--;
        if (vmaddr >= mapping->vmaddr && (searchEndAddr < mappingEndAddr)) {
            mappingOut = mapping;
            *stop = true;
        }
    });

    return mappingOut;
}

void *dsc_find_buffer(DyldSharedCache *sharedCache, uint64_t vmaddr, uint64_t size)
{
    DyldSharedCacheMapping *mapping = dsc_lookup_mapping(sharedCache, vmaddr, size);
    if (mapping) {
        return (void *)((uintptr_t)mapping->ptr + (vmaddr - mapping->vmaddr));
    }

    return NULL;
}

int dsc_read_from_vmaddr(DyldSharedCache *sharedCache, uint64_t vmaddr, size_t size, void *outBuf)
{
    uint64_t startAddr = vmaddr;
    uint64_t endAddr = startAddr + size;
    uint64_t curAddr = startAddr;

    while (curAddr < endAddr) {
        DyldSharedCacheMapping *mapping = dsc_lookup_mapping(sharedCache, curAddr, 0);
        if (!mapping) return -1;

        uint64_t startOffset = curAddr - mapping->vmaddr;
        uint64_t mappingRemaining = mapping->size - startOffset;
        uint64_t copySize = endAddr - curAddr;
        if (copySize > mappingRemaining) copySize = mappingRemaining;

        memcpy((void *)((intptr_t)outBuf + (curAddr - startAddr)), (void *)((intptr_t)mapping->ptr + startOffset), copySize);
        curAddr += copySize;
    }

    return 0;
}

int dsc_read_string_from_vmaddr(DyldSharedCache *sharedCache, uint64_t vmaddr, char **outString)
{
    uint64_t len = 0;
    char c = 0;
    do {
        if (dsc_read_from_vmaddr(sharedCache, vmaddr + (len++), sizeof(c), &c) != 0) return -1;
    } while (c != 0);

    *outString = malloc(len);
    return dsc_read_from_vmaddr(sharedCache, vmaddr, len, *outString);
}

uint64_t dsc_fileoff_to_vmaddr(DyldSharedCache *sharedCache, DyldSharedCacheFile *file, uint64_t fileoff)
{
    for (unsigned i = 0; i < sharedCache->mappingCount; i++) {
        DyldSharedCacheMapping *mapping = &sharedCache->mappings[i];
        if (mapping->file == file) {
            if (fileoff >= mapping->fileoff && fileoff < (mapping->fileoff + mapping->size)) {
                return mapping->vmaddr + (fileoff - mapping->fileoff);
            }
        }
    }
    return 0;
}

uint64_t dsc_vmaddr_to_fileoff(DyldSharedCache *sharedCache, uint64_t vmaddr, DyldSharedCacheFile **fileOut)
{
    DyldSharedCacheMapping *mapping = dsc_lookup_mapping(sharedCache, vmaddr, 0);
    if (mapping) {
        if (fileOut) *fileOut = mapping->file;
        return (vmaddr - mapping->vmaddr) + mapping->fileoff;
    }
    return 0;
}

DyldSharedCacheFile *_dsc_load_file(const char *dscPath, const char suffix[32])
{
    int fd = -1;
    DyldSharedCacheFile *file = NULL;

    char filepath[strlen(dscPath) + strnlen(suffix, 32) + 1];
    strcpy(filepath, dscPath);
    strncat(filepath, suffix, 32);

    fd = open(filepath, O_RDONLY);
    if (fd < 0) goto fail;

    struct stat sb;
    if (fstat(fd, &sb) != 0) goto fail;

    if (sb.st_size < sizeof(struct dyld_cache_header)) goto fail;

    file = malloc(sizeof(DyldSharedCacheFile));
    if (!file) goto fail;

    lseek(fd, 0, SEEK_SET);
    read(fd, &file->header, sizeof(file->header));
    
    if (strncmp(file->header.magic, "dyld_v", 6) != 0) goto fail;

    // A lot of version detection works through the mappingOffset attribute
    // This attribute typically points to the end of the header, since the mappings directly follow the header
    // To make certain version detection easier, we zero out any fields after it, since these are unused on the version the DSC is from
    // This reduces the amount of version (mappingOffset) checks neccessary, but does not fully eliminate them
    if (file->header.mappingOffset < sizeof(file->header)) {
        memset((void *)((uintptr_t)&file->header + file->header.mappingOffset), 0, sizeof(file->header) - file->header.mappingOffset);
    }
    else if (file->header.mappingOffset > sizeof(file->header)) {
        static bool versionWarningPrinted = false;
        if (!versionWarningPrinted) {
            fprintf(stderr, "Warning: DSC version is newer than what ChOma supports, your mileage may vary.\n");
            versionWarningPrinted = true;
        }
    }

    file->fd = fd;
    file->filepath = strdup(filepath);
    file->filesize = sb.st_size;
    return file;

fail:
    if (file) free(file);
    if (fd >= 0) close(fd);
    return NULL;
}

int dsc_file_read_at_offset(DyldSharedCacheFile *dscFile, uint64_t offset, size_t size, void *outBuf)
{
    lseek(dscFile->fd, offset, SEEK_SET);
    return !(read(dscFile->fd, outBuf, size) == size);
}

int dsc_file_read_string_at_offset(DyldSharedCacheFile *dscFile, uint64_t offset, char **outBuf)
{
    lseek(dscFile->fd, offset, SEEK_SET);
    return read_string(dscFile->fd, outBuf);
}

DyldSharedCache *dsc_init_from_path_premapped(const char *path, uint32_t premapSlide)
{
    if (!path) return NULL;

    DyldSharedCache *sharedCache = malloc(sizeof(DyldSharedCache));
    sharedCache->mappings = NULL;
    sharedCache->mappingCount = 0;
    sharedCache->symbolFile.index = 0;
    sharedCache->premapSlide = premapSlide;

    // Load main DSC file
    DyldSharedCacheFile *mainFile = _dsc_load_file(path, "");
    if (!mainFile) {
        fprintf(stderr, "Error: Failed to load main cache file\n");
        dsc_free(sharedCache);
        return NULL;
    }

    struct dyld_cache_header *mainHeader = &mainFile->header;
    if (!strncmp(mainHeader->magic, "dyld_v1  armv7", 14)) {
        sharedCache->cputype = CPU_TYPE_ARM;
        sharedCache->cpusubtype = CPU_SUBTYPE_ARM_V7;
    }
    else if (!strncmp(mainHeader->magic, "dyld_v1  arm64", 14)) {
        sharedCache->cputype = CPU_TYPE_ARM64;
        sharedCache->cpusubtype = CPU_SUBTYPE_ARM64_ALL;
    }
    else if (!strncmp(mainHeader->magic, "dyld_v1  arm64e", 15)) {
        sharedCache->cputype = CPU_TYPE_ARM64;
        sharedCache->cpusubtype = CPU_SUBTYPE_ARM64E;
    }
    else {
        // Only arm supported for now
        printf("Error: DSC has unsupported architecture\n");
        return NULL;
    }

    bool symbolFileExists = !!memcmp(mainHeader->symbolFileUUID, UUID_NULL, sizeof(UUID_NULL));
    uint32_t subCacheArrayCount = mainHeader->subCacheArrayCount;

    sharedCache->fileCount = 1 + subCacheArrayCount + symbolFileExists;

    sharedCache->files = malloc(sizeof(struct DyldSharedCacheFile *) * sharedCache->fileCount);
    sharedCache->files[0] = mainFile;

    if (subCacheArrayCount > 0) {
        // If there are sub caches, load them aswell
        int subCacheStructVersion = mainHeader->mappingOffset <= offsetof(struct dyld_cache_header, cacheSubType) ? 1 : 2;

        for (uint32_t i = 0; i < subCacheArrayCount; i++) {
            DyldSharedCacheFile **file = &sharedCache->files[1+i];
            struct dyld_subcache_entry subcacheEntry;
            
            if (subCacheStructVersion == 1) {
                struct dyld_subcache_entry_v1 v1Entry;
                dsc_file_read_at_offset(mainFile, mainHeader->subCacheArrayOffset + sizeof(v1Entry) * i, sizeof(v1Entry), &v1Entry);
                
                // Old format (iOS <=15) had no suffix string, here the suffix is derived from the index
                memcpy(subcacheEntry.uuid, v1Entry.uuid, sizeof(uuid_t));
                subcacheEntry.cacheVMOffset = v1Entry.cacheVMOffset;
                snprintf(subcacheEntry.fileSuffix, sizeof(subcacheEntry.fileSuffix), ".%u", i+1);
            }
            else {
                dsc_file_read_at_offset(mainFile, mainHeader->subCacheArrayOffset + sizeof(subcacheEntry) * i, sizeof(subcacheEntry), &subcacheEntry);
            }

            *file = _dsc_load_file(path, subcacheEntry.fileSuffix);
            if (!*file) {
                fprintf(stderr, "Error: Failed to map subcache with suffix %s\n", subcacheEntry.fileSuffix);
                dsc_free(sharedCache);
                return NULL;
            }

            struct dyld_cache_header *header = &(*file)->header;
            if (memcmp(header->uuid, subcacheEntry.uuid, sizeof(header->uuid)) != 0) {
                fprintf(stderr, "Error: UUID mismatch on subcache with suffix %s\n", subcacheEntry.fileSuffix);
                dsc_free(sharedCache);
                return NULL;
            }
        }
    }

    if (symbolFileExists) {
        // If there is a .symbols file, load that aswell and use it for getting symbols
        sharedCache->symbolFile.index = sharedCache->fileCount - 1;

        sharedCache->files[sharedCache->symbolFile.index] = _dsc_load_file(path, ".symbols");
        if (!sharedCache->files[sharedCache->symbolFile.index]) {
            fprintf(stderr, "Error: Failed to map symbols subcache\n");
            dsc_free(sharedCache);
            return NULL;
        }

        struct dyld_cache_header *header = &sharedCache->files[sharedCache->symbolFile.index]->header;
        if (memcmp(header->uuid, mainHeader->symbolFileUUID, sizeof(header->uuid)) != 0) {
            fprintf(stderr, "Error: UUID mismatch on symbols subcache\n");
            dsc_free(sharedCache);
            return NULL;
        }
    }

    sharedCache->baseAddress = mainHeader->sharedRegionStart ?: UINT64_MAX;

    for (unsigned i = 0; i < sharedCache->fileCount; i++) {
        DyldSharedCacheFile *file = sharedCache->files[i];
        if (!file) continue;

        if (i != 0 && i == sharedCache->symbolFile.index) {
            // If there is a separate .symbols file (and we don't use the main shared cache for symbols)
            // then skip any mappings inside it, since this usually only contains a bogus mapping
            continue;
        }

        struct dyld_cache_header *header = &file->header;

        //printf("Parsing DSC %s\n", file->filepath);

        if (file->filesize < (header->mappingOffset + header->mappingCount * sizeof(struct dyld_cache_mapping_info))) {
            fprintf(stderr, "Warning: Failed to parse DSC %s.\n", file->filepath);
        }

        bool slideInfoExists = (bool)header->mappingWithSlideOffset;
        uint64_t mappingOffset = (slideInfoExists ? header->mappingWithSlideOffset : header->mappingOffset);

        unsigned prevMappingCount = sharedCache->mappingCount;
        sharedCache->mappingCount += header->mappingCount;
        sharedCache->mappings = realloc(sharedCache->mappings, sharedCache->mappingCount * sizeof(DyldSharedCacheMapping));

        for (int k = 0; k < header->mappingCount; k++) {
            DyldSharedCacheMapping *thisMapping = &sharedCache->mappings[prevMappingCount + k];

            struct dyld_cache_mapping_and_slide_info fullInfo = {};
            if (slideInfoExists) {
                dsc_file_read_at_offset(file, mappingOffset + (k * sizeof(fullInfo)), sizeof(fullInfo), &fullInfo);
            }
            else {
                struct dyld_cache_mapping_info mappingInfo;
                dsc_file_read_at_offset(file, mappingOffset + k * sizeof(mappingInfo), sizeof(mappingInfo), &mappingInfo);

                fullInfo.address = mappingInfo.address;
                fullInfo.size = mappingInfo.size;
                fullInfo.fileOffset = mappingInfo.fileOffset;
                fullInfo.maxProt = mappingInfo.maxProt;
                fullInfo.initProt = mappingInfo.initProt;
                fullInfo.slideInfoFileOffset = 0;
                fullInfo.slideInfoFileSize = 0;
            }

            thisMapping->file = file;
            thisMapping->size = fullInfo.size;
            thisMapping->fileoff = fullInfo.fileOffset;
            thisMapping->vmaddr = fullInfo.address;
            thisMapping->flags = fullInfo.flags;
            if (sharedCache->premapSlide) {
                thisMapping->ptr = (void *)(thisMapping->vmaddr + sharedCache->premapSlide);
            }
            else {
                thisMapping->ptr = mmap(NULL, thisMapping->size, PROT_READ, MAP_FILE | MAP_SHARED, file->fd, thisMapping->fileoff);
            }

            // Find base address on shared caches that don't have sharedRegionStart
            if (!mainHeader->sharedRegionStart) {
                if (thisMapping->vmaddr < sharedCache->baseAddress) {
                    sharedCache->baseAddress = thisMapping->vmaddr;
                }
            }

            thisMapping->initProt = fullInfo.initProt;
            thisMapping->maxProt = fullInfo.maxProt;

            if (fullInfo.slideInfoFileOffset) {
                thisMapping->slideInfoSize = fullInfo.slideInfoFileSize;
                thisMapping->slideInfoPtr = malloc(thisMapping->slideInfoSize);
                dsc_file_read_at_offset(file, fullInfo.slideInfoFileOffset, thisMapping->slideInfoSize, thisMapping->slideInfoPtr);
            }
            else {
                thisMapping->slideInfoPtr = NULL;
                thisMapping->slideInfoSize = 0;
            }
        }
    }

    if (mainHeader->imagesTextCount) {
        struct dyld_cache_image_text_info imageTexts[mainHeader->imagesTextCount];
        dsc_file_read_at_offset(mainFile, mainHeader->imagesTextOffset, sizeof(imageTexts), imageTexts);
        
        sharedCache->containedImageCount = mainHeader->imagesTextCount;
        sharedCache->containedImages = malloc(mainHeader->imagesTextCount * sizeof(DyldSharedCacheImage));
        for (uint64_t i = 0; i < mainHeader->imagesTextCount; i++) {
            struct dyld_cache_image_text_info *imageTextInfo = &imageTexts[i];
            DyldSharedCacheImage *image = &sharedCache->containedImages[i];

            image->address = imageTextInfo->loadAddress;
            image->size = imageTextInfo->textSegmentSize;

            void *buffer = dsc_find_buffer(sharedCache, image->address, image->size);
            if (!buffer) {
                continue;
            }

            image->index = i;

            memcpy(&image->uuid, &imageTextInfo->uuid, sizeof(uuid_t));

            dsc_file_read_string_at_offset(mainFile, imageTextInfo->pathOffset, &image->path);

            MemoryStream *stream = buffered_stream_init_from_buffer_nocopy(buffer, image->size, 0);
            image->fat = fat_dsc_init_from_memory_stream(stream, sharedCache, image);
        }
    }
    else {
        uint64_t imagesOffset = mainHeader->imagesOffsetOld ?: mainHeader->imagesOffset;
        uint64_t imagesCount  = mainHeader->imagesCountOld ?: mainHeader->imagesCount;

        struct dyld_cache_image_info imageInfos[imagesCount];
        dsc_file_read_at_offset(mainFile, imagesOffset, sizeof(imageInfos), imageInfos);

        sharedCache->containedImageCount = imagesCount;
        sharedCache->containedImages = malloc(imagesCount * sizeof(DyldSharedCacheImage));
        for (uint64_t i = 0; i < imagesCount; i++) {
            DyldSharedCacheImage *image = &sharedCache->containedImages[i];
            
            // There is no size in this format, so we need to calculate it 
            // Either based on the image after it or based on the end of the mapping
            DyldSharedCacheMapping *mappingForThisImage = dsc_lookup_mapping(sharedCache, imageInfos[i].address, 0);
            if (!mappingForThisImage) {
                continue;
            }

            uint64_t mappingEndAddr = mappingForThisImage->vmaddr + mappingForThisImage->size;

            // Some images have the same address and also the list is not sorted
            // So we need to traverse it to find the next image after this one
            uint64_t endAddr = UINT64_MAX;
            for (int k = 0; k < imagesCount; k++) {
                if (imageInfos[k].address > imageInfos[i].address) {
                    if (endAddr > imageInfos[k].address) {
                        endAddr = imageInfos[k].address;
                        break;
                    }
                }
            }

            // If there was no image after it or the image after it is in a different mapping
            // Use the end of the mapping as the end address
            if (endAddr > mappingEndAddr) {
                endAddr = mappingEndAddr;
            }

            image->address = imageInfos[i].address;
            image->size = endAddr - imageInfos[i].address;

            void *buffer = dsc_find_buffer(sharedCache, image->address, image->size);
            if (!buffer) {
                continue;
            }

            image->index = i;

            dsc_file_read_string_at_offset(mainFile, imageInfos[i].pathFileOffset, &image->path);

            MemoryStream *stream = buffered_stream_init_from_buffer_nocopy(buffer, image->size, 0);
            image->fat = fat_dsc_init_from_memory_stream(stream, sharedCache, &sharedCache->containedImages[i]);
        }
    }

    return sharedCache;
}

int _dsc_load_symbols(DyldSharedCache *sharedCache)
{
    if (!sharedCache->symbolFile.loaded) {
        if (sharedCache->symbolFile.index != -1) {
            DyldSharedCacheFile *symbolCacheFile = sharedCache->files[sharedCache->symbolFile.index];
            struct dyld_cache_header *symbolCacheHeader = &symbolCacheFile->header;
            if (symbolCacheHeader->localSymbolsOffset) {
                struct dyld_cache_local_symbols_info symbolsInfo;
                dsc_file_read_at_offset(symbolCacheFile, symbolCacheHeader->localSymbolsOffset, sizeof(symbolsInfo), &symbolsInfo);

                for (uint64_t i = 0; i < symbolsInfo.entriesCount; i++) {
                    uint64_t dylibOffset = 0;
                    uint32_t nlistStartIndex = 0;
                    uint32_t nlistCount = 0;
                    int r = 0;

                    #define _GENERIC_READ_SYMBOL_ENTRY(entryType) do { \
                        struct entryType symbolEntry; \
                        if ((r = dsc_file_read_at_offset(symbolCacheFile, symbolCacheHeader->localSymbolsOffset + symbolsInfo.entriesOffset + i * sizeof(symbolEntry), sizeof(symbolEntry), &symbolEntry)) != 0) break; \
                        dylibOffset = symbolEntry.dylibOffset; \
                        nlistStartIndex = symbolEntry.nlistStartIndex; \
                        nlistCount = symbolEntry.nlistCount; \
                    } while (0)

                    if (symbolCacheHeader->mappingOffset >= offsetof(struct dyld_cache_header, symbolFileUUID)) {
                        _GENERIC_READ_SYMBOL_ENTRY(dyld_cache_local_symbols_entry_64);
                    }
                    else {
                        _GENERIC_READ_SYMBOL_ENTRY(dyld_cache_local_symbols_entry);
                    }

                    if (r != 0) continue;

                    #undef _GENERIC_READ_SYMBOL_ENTRY

                    DyldSharedCacheImage *image = dsc_lookup_image_by_address(sharedCache, sharedCache->baseAddress + dylibOffset);
                    if (image) {
                        image->nlistCount = nlistCount;
                        image->nlistStartIndex = nlistStartIndex;
                    }
                }

                sharedCache->symbolFile.nlistCount = symbolsInfo.nlistCount;
                uint64_t nlistSize = (dsc_is32bit(sharedCache) ? sizeof(struct nlist) : sizeof(struct nlist_64)) * sharedCache->symbolFile.nlistCount;
                sharedCache->symbolFile.nlist = malloc(nlistSize);
                dsc_file_read_at_offset(symbolCacheFile, symbolCacheHeader->localSymbolsOffset + symbolsInfo.nlistOffset, nlistSize, sharedCache->symbolFile.nlist);

                uint64_t stringsOffsetPage = (symbolCacheHeader->localSymbolsOffset + symbolsInfo.stringsOffset) & ~PAGE_MASK;
                uint64_t stringsOffsetPageOff = (symbolCacheHeader->localSymbolsOffset + symbolsInfo.stringsOffset) & PAGE_MASK;

                sharedCache->symbolFile.stringsSize = symbolsInfo.stringsSize;
                
                char *mappedStrings = mmap(NULL, sharedCache->symbolFile.stringsSize + stringsOffsetPageOff, PROT_READ, MAP_FILE | MAP_PRIVATE, symbolCacheFile->fd, stringsOffsetPage);
                if (mappedStrings != MAP_FAILED) {
                    sharedCache->symbolFile.strings = mappedStrings + stringsOffsetPageOff;
                }
                else {
                    perror("mmap");
                }
            }
        }

        sharedCache->symbolFile.loaded = true;
    }

    return sharedCache->symbolFile.nlist ? 0 : -1;
}

DyldSharedCache *dsc_init_from_path(const char *path)
{
    return dsc_init_from_path_premapped(path, 0);
}

bool dsc_is32bit(DyldSharedCache *sharedCache)
{
    if (sharedCache->cputype == CPU_TYPE_ARM) {
        return true;
    }
    else {
        return false;
    }
}

void dsc_enumerate_files(DyldSharedCache *sharedCache, void (^enumeratorBlock)(const char *filepath, size_t filesize, struct dyld_cache_header *header))
{
    for (int i = 0; i < sharedCache->fileCount; i++) {
        enumeratorBlock(sharedCache->files[i]->filepath, sharedCache->files[i]->filesize, &sharedCache->files[i]->header);
    }
}

void dsc_enumerate_images(DyldSharedCache *sharedCache, void (^enumeratorBlock)(const char *path, DyldSharedCacheImage *imageHandle, MachO *imageMachO, bool *stop))
{
    for (unsigned i = 0; i < sharedCache->containedImageCount; i++) {
        bool stop = false;
        DyldSharedCacheImage *imageHandle = &sharedCache->containedImages[i];
        MachO *macho = fat_get_single_slice(imageHandle->fat);
        if (imageHandle && macho) {
            enumeratorBlock(sharedCache->containedImages[i].path, imageHandle, macho, &stop);
        }
        if (stop) break;
    }
}

DyldSharedCacheImage *dsc_find_image_for_section_address(DyldSharedCache *sharedCache, uint64_t address)
{
    __block DyldSharedCacheImage *image = NULL;
    for (unsigned i = 0; i < sharedCache->containedImageCount; i++) {
        if (sharedCache->containedImages[i].fat->slicesCount == 1) {
            MachO *macho = sharedCache->containedImages[i].fat->slices[0];
            if (macho) {
                macho_enumerate_sections(macho, ^(struct section_64 *section, struct segment_command_64 *segment, bool *stop) {
                    if (address >= section->addr && address < (section->addr + section->size)) {
                        image = &sharedCache->containedImages[i];
                    }
                });
            }
        }
    }
    return image;
}

MachO *dsc_image_get_macho(DyldSharedCacheImage *image)
{
    return fat_get_single_slice(image->fat);
}

DyldSharedCacheImage *dsc_lookup_image_by_address(DyldSharedCache *sharedCache, uint64_t address)
{
    __block DyldSharedCacheImage *image = NULL;
    for (unsigned i = 0; i < sharedCache->containedImageCount; i++) {
        MachO *macho = dsc_image_get_macho(&sharedCache->containedImages[i]);
        struct segment_command_64 segment;
        if (macho_lookup_segment_by_addr(macho, address, &segment) == 0) {
            image = &sharedCache->containedImages[i];
        }
        if (image) break;
    }
    return image;
}

MachO *dsc_lookup_macho_by_address(DyldSharedCache *sharedCache, uint64_t address, DyldSharedCacheImage **imageHandleOut)
{
    DyldSharedCacheImage *image = dsc_lookup_image_by_address(sharedCache, address);
    if (image) {
        if (imageHandleOut) *imageHandleOut = image;
        return dsc_image_get_macho(image);
    }
    return NULL;
}

DyldSharedCacheImage *dsc_lookup_image_by_path(DyldSharedCache *sharedCache, const char *path)
{
    for (unsigned i = 0; i < sharedCache->containedImageCount; i++) {
        if (!strcmp(sharedCache->containedImages[i].path, path)) {
            return &sharedCache->containedImages[i];
        }
    }
    return NULL;
}

MachO *dsc_lookup_macho_by_path(DyldSharedCache *sharedCache, const char *path, DyldSharedCacheImage **imageHandleOut)
{
    DyldSharedCacheImage *image = dsc_lookup_image_by_path(sharedCache, path);
    if (image) {
        if (imageHandleOut) *imageHandleOut = image;
        return dsc_image_get_macho(image);
    }
    return NULL;
}

int dsc_image_enumerate_symbols(DyldSharedCache *sharedCache, DyldSharedCacheImage *image, void (^enumeratorBlock)(const char *name, uint8_t type, uint64_t vmaddr, bool *stop))
{
    if (_dsc_load_symbols(sharedCache) != 0) return -1;

    struct dyld_cache_header *symbolCacheHeader = &sharedCache->files[sharedCache->symbolFile.index]->header;
    if (!symbolCacheHeader->localSymbolsOffset) return -1;
    
    char *stringTable = sharedCache->symbolFile.strings;

    uint32_t firstSymIdx = image->nlistStartIndex;
    uint32_t lastSymIdx = image->nlistStartIndex + image->nlistCount - 1;
    if (lastSymIdx > sharedCache->symbolFile.nlistCount) return -1;
    
    for (uint32_t symIdx = firstSymIdx; symIdx <= lastSymIdx; symIdx++) {
        uint64_t n_strx = 0;
        uint64_t n_value = 0;
        uint8_t n_type = 0;

        #define _GENERIC_READ_NLIST(nlistType) do { \
            struct nlistType *entry = &((struct nlistType *)sharedCache->symbolFile.nlist)[symIdx]; \
            n_strx = entry->n_un.n_strx; \
            n_value = entry->n_value; \
            n_type = entry->n_type; \
        } while (0)

        if (dsc_is32bit(sharedCache)) {
            _GENERIC_READ_NLIST(nlist);
        }
        else {
            _GENERIC_READ_NLIST(nlist_64);
        }

        #undef _GENERIC_READ_NLIST

        if (n_strx > sharedCache->symbolFile.stringsSize) return -1;

        bool stop = false;
        enumeratorBlock(&stringTable[n_strx], n_type, n_value, &stop);
        if (stop) break;
    }

    return 0;
}

int dsc_image_enumerate_patches(DyldSharedCache *sharedCache, DyldSharedCacheImage *image, void (^enumeratorBlock)(unsigned v, void *patchable_location, bool *stop))
{
    struct dyld_cache_header *mainHeader = &sharedCache->files[0]->header;

    struct dyld_cache_patch_info_v3 *patchInfo = dsc_find_buffer(sharedCache, mainHeader->patchInfoAddr, mainHeader->patchInfoSize);

    if (patchInfo->infoV2.patchTableVersion == 4) {
        struct dyld_cache_image_got_clients_v3 *gotClients = (void *)((uintptr_t)patchInfo + (patchInfo->gotClientsArrayAddr - mainHeader->patchInfoAddr));
        struct dyld_cache_patchable_export_v3 *clientExports = (void *)((uintptr_t)patchInfo + (patchInfo->gotClientExportsArrayAddr - mainHeader->patchInfoAddr));
        struct dyld_cache_patchable_location_v4 *locationArray = (void *)((uintptr_t)patchInfo + (patchInfo->gotLocationArrayAddr - mainHeader->patchInfoAddr));

        uint32_t patchExportsStartIndex = gotClients[image->index].patchExportsStartIndex;
        uint32_t patchExportsEndIndex = patchExportsStartIndex + gotClients[image->index].patchExportsCount;
        for (uint32_t i = patchExportsStartIndex; i < patchExportsEndIndex; i++) {
            uint32_t patchLocationsStartIndex = clientExports[i].patchLocationsStartIndex;
            uint32_t patchLocationsEndIndex = patchLocationsStartIndex + clientExports[i].patchLocationsCount;
            for (uint32_t k = clientExports[i].patchLocationsStartIndex; k < patchLocationsEndIndex; k++) {
                bool stop = false;
                enumeratorBlock(4, &locationArray[k], &stop);
                if (stop) return 0;
            }
        }
    }

    return 0;
}

int dsc_mapping_enumerate_chained_fixups_on_range(DyldSharedCache *sharedCache, DyldSharedCacheMapping *mapping, uint64_t rangeStart, uint64_t rangeEnd, void (^enumeratorBlock)(DyldSharedCachePointer *pointer, bool *stop))
{
    if (!mapping->slideInfoPtr) return -1;
    if (sharedCache->premapSlide != 0) return -1; // XXX: Not supported on premapped dscs

    uint32_t version = *(uint32_t *)mapping->slideInfoPtr;
    switch (version) {
        case 5: {
            struct dyld_cache_slide_info5 *info = mapping->slideInfoPtr;
            uint64_t startAddr = mapping->vmaddr;
            uint64_t endAddr = startAddr + (info->page_starts_count * info->page_size);

            uint64_t pageMask = info->page_size - 1;
            bool hasRange = false;

            if (rangeStart != 0 && rangeEnd != 0) {
                if (rangeStart < startAddr || rangeStart >= endAddr) return -1;
                startAddr = rangeStart & ~pageMask;
                if (rangeEnd <= startAddr || rangeEnd > endAddr) return -1;
                endAddr = (rangeEnd + pageMask) & ~pageMask;
                hasRange = true;
            }

            for (uint64_t pageAddr = startAddr; pageAddr < endAddr; pageAddr += info->page_size) {
                uint64_t pageIdx = (pageAddr - mapping->vmaddr) / info->page_size;
                uint32_t delta = info->page_starts[pageIdx];
                union dyld_cache_slide_pointer5* loc = (mapping->ptr + (pageAddr - mapping->vmaddr));
                if (delta != DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE) {
                    delta /= 8; // The first delta is a direct offset, all further ones are (offset / 8)
                    do {
                        loc += delta;
                        delta = loc->auth.next;

                        uint64_t value = loc->regular.runtimeOffset + info->value_add;
                        if (!loc->auth.auth) {
                            value |= ((uint64_t)loc->regular.high8 << 56);
                        }

                        DyldSharedCachePointer pointer = (DyldSharedCachePointer){
                            .location = ((uint64_t)loc - (uint64_t)mapping->ptr) + mapping->vmaddr,
                            .target = value,

                            .authenticated = loc->auth.auth,
                            .key = loc->auth.keyIsData ? PAC_KEY_DA : PAC_KEY_IA,
                            .diversifier = loc->auth.diversity,
                            .hasAddressDiversity = loc->auth.addrDiv,
                        };

                        if (hasRange) {
                            if (pointer.location < rangeStart) continue;
                            if (pointer.location >= rangeEnd) break;
                        }

                        bool stop = false;
                        enumeratorBlock(&pointer, &stop);
                        if (stop) return 0;
                    } while (delta != 0);
                }
            }
            break;
        }
        // XXX: What actually uses version 4???
        case 3: {
            struct dyld_cache_slide_info3 *info = mapping->slideInfoPtr;
            uint64_t startAddr = mapping->vmaddr;
            uint64_t endAddr = startAddr + (info->page_starts_count * info->page_size);

            uint64_t pageMask = info->page_size - 1;
            bool hasRange = false;

            if (rangeStart != 0 && rangeEnd != 0) {
                if (rangeStart < startAddr || rangeStart >= endAddr) return -1;
                startAddr = rangeStart & ~pageMask;
                if (rangeEnd <= startAddr || rangeEnd > endAddr) return -1;
                endAddr = (rangeEnd + pageMask) & ~pageMask;
                hasRange = true;
            }

            for (uint64_t pageAddr = startAddr; pageAddr < endAddr; pageAddr += info->page_size) {
                uint64_t pageIdx = (pageAddr - mapping->vmaddr) / info->page_size;
                uint32_t delta = info->page_starts[pageIdx];
                union dyld_cache_slide_pointer3* loc = (mapping->ptr + (pageAddr - mapping->vmaddr));
                if (delta != DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE) {
                    delta /= 8; // The first delta is a direct offset, all further ones are (offset / 8)
                    do {
                        loc += delta;
                        delta = loc->auth.offsetToNextPointer;

                        uint64_t value = 0;
                        if (loc->auth.authenticated) {
                            value = loc->auth.offsetFromSharedCacheBase + info->auth_value_add;
                        }
                        else {
                            uint64_t value51 = loc->plain.pointerValue;
                            uint64_t top8Bits = value51 & 0x0007F80000000000ULL;
                            uint64_t bottom43Bits = value51 & 0x000007FFFFFFFFFFULL;
                            value = (top8Bits << 13) | bottom43Bits;
                        }

                        DyldSharedCachePointer pointer = (DyldSharedCachePointer){
                            .location = ((uint64_t)loc - (uint64_t)mapping->ptr) + mapping->vmaddr,
                            .target = value,

                            .authenticated = loc->auth.authenticated,
                            .key = loc->auth.key,
                            .diversifier = loc->auth.diversityData,
                            .hasAddressDiversity = loc->auth.hasAddressDiversity,
                        };

                        if (hasRange) {
                            if (pointer.location < rangeStart) continue;
                            if (pointer.location >= rangeEnd) break;
                        }

                        bool stop = false;
                        enumeratorBlock(&pointer, &stop);
                        if (stop) return 0;
                    } while (delta != 0);
                }
            }
            break;
        }
        case 2: {
            struct dyld_cache_slide_info2 *info = mapping->slideInfoPtr;

            uint16_t *pageStarts = (uint16_t *)((uintptr_t)info + info->page_starts_offset);
            uint16_t *pageExtras = (uint16_t *)((uintptr_t)info + info->page_extras_offset);
            uint64_t deltaMask = info->delta_mask;
            uint64_t valueMask = ~deltaMask;
            uint64_t deltaShift = __builtin_ctzll(deltaMask) - 2;

            uint64_t startAddr = mapping->vmaddr;
            uint64_t endAddr = startAddr + (info->page_starts_count * info->page_size);

            uint64_t pageMask = info->page_size - 1;
            bool hasRange = false;

            if (rangeStart != 0 && rangeEnd != 0) {
                if (rangeStart < startAddr || rangeStart >= endAddr) return -1;
                startAddr = rangeStart & ~pageMask;
                if (rangeEnd <= startAddr || rangeEnd > endAddr) return -1;
                endAddr = (rangeEnd + pageMask) & ~pageMask;
                hasRange = true;
            }

            for (uint64_t pageAddr = startAddr; pageAddr < endAddr; pageAddr += info->page_size) {
                uint64_t pageIdx = (pageAddr - mapping->vmaddr) / info->page_size;
                uint16_t pageEntry = pageStarts[pageIdx];
                if (pageEntry == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) continue;

                int (^processChain)(uint32_t pageOffset) = ^(uint32_t pageOffset) {
                    uint32_t delta = 1;
                    while (delta != 0) {
                        uint64_t locAddr = pageAddr + pageOffset;
                        uint64_t rawValue = 0;
                        dsc_read_from_vmaddr(sharedCache, locAddr, dsc_is32bit(sharedCache) ? sizeof(uint32_t) : sizeof(uint64_t), &rawValue);
                        delta = (uint32_t)((rawValue & deltaMask) >> deltaShift);
                        uint64_t target = (rawValue & valueMask);
                        if (target != 0) {
                            target += info->value_add;
                        }
                        pageOffset += delta;

                        DyldSharedCachePointer pointer = (DyldSharedCachePointer){
                            .location = locAddr,
                            .target = target,

                            .authenticated = false,
                            .key = 0,
                            .diversifier = 0,
                            .hasAddressDiversity = false,
                        };

                        if (hasRange) {
                            if (pointer.location < rangeStart) continue;
                            if (pointer.location >= rangeEnd) break;
                        }

                        bool stop = false;
                        enumeratorBlock(&pointer, &stop);
                        if (stop) return 0;
                    }
                    return 1;
                };

                if (pageEntry == DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) {
                    uint16_t chainIdx = (pageEntry & 0x3fff);
                    bool done = false;
                    while (!done) {
                        uint16_t pInfo = pageExtras[chainIdx];
                        uint32_t pageStartOffset = (pInfo & 0x3fff) * 4;
                        int r = processChain(pageStartOffset);
                        if (r == 0) return 0;
                        done = (pInfo & DYLD_CACHE_SLIDE_PAGE_ATTR_END);
                        chainIdx++;
                    }
                }
                else {
                    uint32_t pageStartOffset = pageEntry * 4;
                    int r = processChain(pageStartOffset);
                    if (r == 0) return 0;
                }
            }
            break;
        }
        default: {
            static bool didShowUnsupportedWarning = false;
            if (!didShowUnsupportedWarning) {
                fprintf(stderr, "Warning: Unsupported chained fixup version (%u)\n", version);
                didShowUnsupportedWarning = true;
            }
        }
        break;
    }

    return 0;
}

int dsc_mapping_enumerate_chained_fixups(DyldSharedCache *sharedCache, DyldSharedCacheMapping *mapping, void (^enumeratorBlock)(DyldSharedCachePointer *pointer, bool *stop))
{
    return dsc_mapping_enumerate_chained_fixups_on_range(sharedCache, mapping, 0, 0, enumeratorBlock);
}

int dsc_enumerate_chained_fixups(DyldSharedCache *sharedCache, void (^enumeratorBlock)(DyldSharedCachePointer *pointer, bool *stop))
{
    for (uint64_t i = 0; i < sharedCache->mappingCount; i++) {
        __block bool stopAll = false;
        DyldSharedCacheMapping *mapping = &sharedCache->mappings[i];
        dsc_mapping_enumerate_chained_fixups(sharedCache, mapping, ^(DyldSharedCachePointer *pointer, bool *stop) {
            enumeratorBlock(pointer, &stopAll);
            *stop = stopAll;
        });
        if (stopAll) break;
    }
    return 0;
}

int dsc_image_enumerate_chained_fixups(DyldSharedCache *sharedCache, DyldSharedCacheImage *image, void (^enumeratorBlock)(DyldSharedCachePointer *pointer, bool *stop))
{
    /*
    Please note that in iOS 18 and macOS Sonoma, GOTs were unified and they are no longer associated to the image machos
    This means multiple images use the same GOTs, which intern means this function will not enumerate over them
    This might be fixable by parsing the __auth_stub functions, but that is non trivial
    */
    MachO *macho = fat_get_single_slice(image->fat);
    if (macho) {
        __block bool stopAll = false;
        macho_enumerate_segments(macho, ^(struct segment_command_64 *segment, bool *stop) {
            //printf("%.*s %#llx %#llx\n", (int)sizeof(segment->segname), segment->segname, segment->vmaddr, segment->vmsize);
            if (!strncmp(segment->segname, "__DATA", 6)) /*__DATA, __DATA_DIRTY, __DATA_CONST */ {
                DyldSharedCacheMapping* mapping = dsc_lookup_mapping(sharedCache, segment->vmaddr, segment->vmsize);
                if (mapping) {
                    dsc_mapping_enumerate_chained_fixups_on_range(sharedCache, mapping, segment->vmaddr, segment->vmaddr + segment->vmsize, ^(DyldSharedCachePointer *pointer, bool *stop2){
                        enumeratorBlock(pointer, &stopAll);
                        *stop2 = stopAll;
                    });
                }
            }
            *stop = stopAll;
        });
    }
    return 0;
}

uint64_t dsc_get_base_address(DyldSharedCache *sharedCache)
{
    return sharedCache->baseAddress;
}

void dsc_free(DyldSharedCache *sharedCache)
{
    if (sharedCache->fileCount > 0) {
        for (unsigned i = 0; i < sharedCache->fileCount; i++) {
            close(sharedCache->files[i]->fd);
            free(sharedCache->files[i]->filepath);
            free(sharedCache->files[i]);
        }
        free(sharedCache->files);
    }
    if (sharedCache->mappings) {
        for (unsigned i = 0; i < sharedCache->mappingCount; i++) {
            if (!sharedCache->premapSlide && sharedCache->mappings[i].ptr) {
                munmap(sharedCache->mappings[i].ptr, sharedCache->mappings[i].size);
            }
            if (sharedCache->mappings[i].slideInfoPtr) {
                free(sharedCache->mappings[i].slideInfoPtr);
            }
        }
        free(sharedCache->mappings);
    }
    if (sharedCache->containedImages) {
        for (unsigned i = 0; i < sharedCache->containedImageCount; i++) {
            if (sharedCache->containedImages[i].path) {
                free(sharedCache->containedImages[i].path);
            }
            if (sharedCache->containedImages[i].fat) {
                fat_free(sharedCache->containedImages[i].fat);
            }
        }
        free(sharedCache->containedImages);
    }
    if (sharedCache->symbolFile.strings) {
        uintptr_t stringsPage = (uintptr_t)sharedCache->symbolFile.strings & ~PAGE_MASK;
        uintptr_t stringsPageOff = (uintptr_t)sharedCache->symbolFile.strings & PAGE_MASK;
        munmap((void *)stringsPage, sharedCache->symbolFile.stringsSize + stringsPageOff);
    }
    if (sharedCache->symbolFile.nlist) {
        free(sharedCache->symbolFile.nlist);
    }
    free(sharedCache);
}
