#ifndef MACHO_SLICE_H
#define MACHO_SLICE_H

#include <stdbool.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include "MemoryStream.h"
#include "Fat.h"
#include "DyldSharedCache.h"

typedef struct MachOSegment
{
    struct segment_command_64 command;
    struct section_64 sections[];
} __attribute__((__packed__)) MachOSegment;

typedef struct FilesetMachO {
    char *entry_id;
    uint64_t vmaddr;
    uint64_t fileoff;
	Fat *underlyingMachO;
} FilesetMachO;

typedef struct MachO {
    MemoryStream *stream;
    bool is32Bit;
    struct mach_header machHeader;
    struct fat_arch_64 archDescriptor;
    uint64_t cachedBase;

    uint32_t filesetCount;
    FilesetMachO *filesetMachos;

    uint32_t segmentCount;
    MachOSegment **segments;

    DyldSharedCache *containingCache;
    DyldSharedCacheImage *cacheImage;
} MachO;

// Read data from a MachO at a specified offset
int macho_read_at_offset(MachO *macho, uint64_t offset, size_t size, void *outBuf);

// Write data from a MachO at a specified offset, auto expands, only works if opened via macho_init_for_writing
int macho_write_at_offset(MachO *macho, uint64_t offset, size_t size, const void *inBuf);

int macho_read_string_at_offset(MachO *macho, uint64_t offset, char **string);
int macho_read_uleb128_at_offset(MachO *macho, uint64_t offset, uint64_t maxOffset, uint64_t *endOffsetOut, uint64_t *valueOut);

MemoryStream *macho_get_stream(MachO *macho);
uint32_t macho_get_filetype(MachO *macho);
struct mach_header *macho_get_mach_header(MachO *macho);
size_t macho_get_mach_header_size(MachO *macho);
DyldSharedCache *macho_get_containing_cache(MachO *macho);

// Perform translation between file offsets and virtual addresses
int macho_translate_fileoff_to_vmaddr(MachO *macho, uint64_t fileoff, uint64_t *vmaddrOut, MachOSegment **segmentOut);
int macho_translate_vmaddr_to_fileoff(MachO *macho, uint64_t vmaddr, uint64_t *fileoffOut, MachOSegment **segmentOut);

// Wrappers to deal with virtual addresses
int macho_read_at_vmaddr(MachO *macho, uint64_t vmaddr, size_t size, void *outBuf);
int macho_write_at_vmaddr(MachO *macho, uint64_t vmaddr, size_t size, const void *inBuf);
int macho_read_string_at_vmaddr(MachO *macho, uint64_t vmaddr, char **outString);
uint64_t macho_get_base_address(MachO *macho);

int macho_enumerate_load_commands(MachO *macho, void (^enumeratorBlock)(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop));
int macho_enumerate_segments(MachO *macho, void (^enumeratorBlock)(struct segment_command_64 *segment, bool *stop));
int macho_enumerate_sections(MachO *macho, void (^enumeratorBlock)(struct section_64 *section, struct segment_command_64 *segment, bool *stop));
int macho_enumerate_symbols(MachO *macho, void (^enumeratorBlock)(const char *name, uint8_t type, uint64_t vmaddr, bool *stop));
int macho_enumerate_dependencies(MachO *macho, void (^enumeratorBlock)(const char *dylibPath, uint32_t cmd, struct dylib* dylib, bool *stop));
int macho_enumerate_rpaths(MachO *macho, void (^enumeratorBlock)(const char *rpath, bool *stop));
int macho_enumerate_function_starts(MachO *macho, void (^enumeratorBlock)(uint64_t funcAddr, bool *stop));

int macho_lookup_segment_by_addr(MachO *macho, uint64_t vmaddr, struct segment_command_64 *segmentOut);
int macho_lookup_section_by_addr(MachO *macho, uint64_t vmaddr, struct section_64 *sectionOut);

// Initialise a MachO object from a MemoryStream and it's corresponding Fat arch descriptor
MachO *macho_init(MemoryStream *stream, struct fat_arch_64 archDescriptor);

// Initialize a single slice macho for writing to it
MachO *macho_init_for_writing(const char *filePath);

// Create an array of MachO objects from an array of paths
MachO **macho_array_create_for_paths(char **inputPaths, int inputPathsCount);

// Check if a MachO is encrypted
bool macho_is_encrypted(MachO *macho);

void macho_free(MachO *macho);

#endif // MACHO_SLICE_H
