#ifndef DYLD_SHARED_CACHE_H
#define DYLD_SHARED_CACHE_H

#include "dyld_cache_format.h"
#include <uuid/uuid.h>
#include "CachePatching.h"
#include <stddef.h>
#include <stdbool.h>
typedef struct MachO MachO;
typedef struct Fat Fat;

typedef struct DyldSharedCacheFile {
	char *filepath;
	size_t filesize;
	int fd;
	struct dyld_cache_header header;
} DyldSharedCacheFile;

typedef struct DyldSharedCacheMapping {
	uint64_t vmaddr;
	uint64_t fileoff;
	void *ptr;
	uint64_t size;
	uint32_t maxProt;
	uint32_t initProt;
	uint64_t flags;
	// ABI stable until here
	void *slideInfoPtr;
	uint64_t slideInfoSize;
	struct DyldSharedCacheFile *file;
} DyldSharedCacheMapping;

typedef struct DyldSharedCacheImage {
	uint64_t address;
	uint64_t size;
	uint64_t index;
	uuid_t uuid;
	char *path;
	uint32_t nlistStartIndex;
	uint32_t nlistCount;
	Fat *fat;
} DyldSharedCacheImage;

typedef struct DyldSharedCache {
	unsigned fileCount;
	DyldSharedCacheFile **files;

	struct {
		bool loaded;
		unsigned index;
		void *nlist;
		uint32_t nlistCount;
		char *strings;
		uint32_t stringsSize;
	} symbolFile;

	unsigned mappingCount;
	DyldSharedCacheMapping *mappings;
	uint64_t baseAddress;
	uint32_t premapSlide;
	uint32_t cputype;
	uint32_t cpusubtype;

	uint64_t containedImageCount;
	DyldSharedCacheImage *containedImages;
} DyldSharedCache;

typedef struct DyldSharedCachePointer {
	uint64_t location;
	uint64_t target;

	bool authenticated;
	uint8_t key;
	uint16_t diversifier;
	bool hasAddressDiversity;
} DyldSharedCachePointer;

enum PAC_KEY {
	PAC_KEY_IA = 0,
	PAC_KEY_IB = 1,
	PAC_KEY_DA = 2,
	PAC_KEY_DB = 3,
};

DyldSharedCache *dsc_init_from_path_premapped(const char *path, uint32_t premapSlide);
DyldSharedCache *dsc_init_from_path(const char *path);
bool dsc_is32bit(DyldSharedCache *sharedCache);
void dsc_enumerate_files(DyldSharedCache *sharedCache, void (^enumeratorBlock)(const char *filepath, size_t filesize, struct dyld_cache_header *header));

void dsc_enumerate_mappings(DyldSharedCache *sharedCache, void (^enumeratorBlock)(DyldSharedCacheMapping *mapping, DyldSharedCacheFile *sourceFile, bool *stop));
DyldSharedCacheMapping *dsc_lookup_mapping(DyldSharedCache *sharedCache, uint64_t vmaddr, uint64_t size);
void *dsc_find_buffer(DyldSharedCache *sharedCache, uint64_t vmaddr, uint64_t size);

int dsc_read_from_vmaddr(DyldSharedCache *sharedCache, uint64_t vmaddr, size_t size, void *outBuf);
int dsc_read_string_from_vmaddr(DyldSharedCache *sharedCache, uint64_t vmaddr, char **outString);
uint64_t dsc_fileoff_to_vmaddr(DyldSharedCache *sharedCache, DyldSharedCacheFile *file, uint64_t fileoff);
uint64_t dsc_vmaddr_to_fileoff(DyldSharedCache *sharedCache, uint64_t vmaddr, DyldSharedCacheFile **fileOut);

void dsc_enumerate_images(DyldSharedCache *sharedCache, void (^enumeratorBlock)(const char *path, DyldSharedCacheImage *imageHandle, MachO *imageMachO, bool *stop));
DyldSharedCacheImage *dsc_find_image_for_section_address(DyldSharedCache *sharedCache, uint64_t address);
MachO *dsc_image_get_macho(DyldSharedCacheImage *image);
DyldSharedCacheImage *dsc_lookup_image_by_address(DyldSharedCache *sharedCache, uint64_t address);
MachO *dsc_lookup_macho_by_address(DyldSharedCache *sharedCache, uint64_t address, DyldSharedCacheImage **imageHandleOut);
DyldSharedCacheImage *dsc_lookup_image_by_path(DyldSharedCache *sharedCache, const char *path);
MachO *dsc_lookup_macho_by_path(DyldSharedCache *sharedCache, const char *path, DyldSharedCacheImage **imageHandleOut);
int dsc_enumerate_chained_fixups(DyldSharedCache *sharedCache, void (^enumeratorBlock)(DyldSharedCachePointer *pointer, bool *stop));

int dsc_image_enumerate_symbols(DyldSharedCache *sharedCache, DyldSharedCacheImage *image, void (^enumeratorBlock)(const char *name, uint8_t type, uint64_t vmaddr, bool *stop));
int dsc_image_enumerate_patches(DyldSharedCache *sharedCache, DyldSharedCacheImage *image, void (^enumeratorBlock)(unsigned v, void *patchable_location, bool *stop));
int dsc_image_enumerate_chained_fixups(DyldSharedCache *sharedCache, DyldSharedCacheImage *image, void (^enumeratorBlock)(DyldSharedCachePointer *pointer, bool *stop));

uint64_t dsc_get_base_address(DyldSharedCache *sharedCache);

void dsc_free(DyldSharedCache *sharedCache);

#endif
