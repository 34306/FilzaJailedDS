#include "Util.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int64_t sxt64(int64_t value, uint8_t bits)
{
    value = ((uint64_t)value) << (64 - bits);
    value >>= (64 - bits);
    return value;
}

int memcmp_masked(const void *str1, const void *str2, unsigned char* mask, size_t n)
{
    const unsigned char* p = (const unsigned char*)str1;
    const unsigned char* q = (const unsigned char*)str2;

    if (p == q) return 0;
    for (int i = 0; i < n; i++) {
        unsigned char cMask = 0xFF;
        if (mask) {
            cMask = mask[i];
        }
        if((p[i] & cMask) != (q[i] & cMask)) {
            // we do not care about 1 / -1
            return -1;
        }
    }

    return 0;
}

uint64_t align_to_size(int size, int alignment)
{
    return (size + alignment - 1) & ~(alignment - 1);
}

void print_hash(uint8_t *hash, size_t size)
{
    for (int j = 0; j < size; j++) {
        printf("%02x", hash[j]);
    }
}

void enumerate_range(uint64_t start, uint64_t end, uint16_t alignment, size_t nbytes, bool (^enumerator)(uint64_t))
{
    if (start == end) return;
    if (alignment == 0) return;
    if (nbytes == 0) return;
    if (nbytes % alignment) return;

    int dir = start < end ? 1 : -1;

    uint64_t absStart = dir == 1 ? start : end;
    uint64_t absEnd   = dir == 1 ? end : start;
    uint64_t absSpace = absEnd - absStart;
    if (alignment > absSpace) return;
    if (absSpace % alignment) return;

    uint64_t absSteps = absSpace / alignment;
    for (uint64_t i = 0; i < absSteps; i++) {
        uint64_t cur = start + (i * alignment * dir) - (dir == -1 ? alignment : 0);
        if (!enumerator(cur)) break;
    }
}

int read_string(int fd, char **strOut)
{
    uint32_t sz = 0;
    off_t pos = lseek(fd, 0, SEEK_CUR);
    char c = 0;
    do {
        if (read(fd, &c, sizeof(c)) != sizeof(c)) return -1;
        sz++;
    } while(c != 0);
    
    lseek(fd, pos, SEEK_SET);
    *strOut = malloc(sz);
    read(fd, *strOut, sz);
    return 0;
}

bool string_has_prefix(const char *str, const char *prefix)
{
    if (!str || !prefix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len) {
		return false;
	}

	return !strncmp(str, prefix, prefix_len);
}

bool string_has_suffix(const char *str, const char *suffix)
{
    if (!str || !suffix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len) {
		return false;
	}

	return !strcmp(str + str_len - suffix_len, suffix);
}
