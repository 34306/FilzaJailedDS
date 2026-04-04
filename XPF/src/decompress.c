// Taken from golb: https://github.com/0x7ff/golb
// Licensed under Apache 2.0
// See decompress.LICENSE

#include "decompress.h"
#include <stdlib.h>
#include <string.h>
#include <compression.h>

#define DER_INT (0x2U)
#define DER_SEQ (0x30U)
#define LZSS_F (18)
#define LZSS_N (4096)
#define LZSS_THRESHOLD (2)
#define KCOMP_HDR_PAD_SZ (0x16C)
#define DER_IA5_STR (0x16U)
#define DER_OCTET_STR (0x4U)
#define KCOMP_HDR_MAGIC (0x636F6D70U)
#define KCOMP_HDR_TYPE_LZSS (0x6C7A7373U)

const uint8_t *
der_decode(uint8_t tag, const uint8_t *der, const uint8_t *der_end, size_t *out_len) {
    size_t der_len;

    if(der_end - der > 2 && tag == *der++) {
        if(((der_len = *der++) & 0x80U) != 0) {
            *out_len = 0;
            if((der_len &= 0x7FU) <= sizeof(*out_len) && (size_t)(der_end - der) >= der_len) {
                while(der_len-- != 0) {
                    *out_len = (*out_len << 8U) | *der++;
                }
            }
        } else {
            *out_len = der_len;
        }
        if(*out_len != 0 && (size_t)(der_end - der) >= *out_len) {
            return der;
        }
    }
    return NULL;
}

const uint8_t *
der_decode_seq(const uint8_t *der, const uint8_t *der_end, const uint8_t **seq_end) {
    size_t der_len;

    if((der = der_decode(DER_SEQ, der, der_end, &der_len)) != NULL) {
        *seq_end = der + der_len;
    }
    return der;
}

const uint8_t *
der_decode_uint64(const uint8_t *der, const uint8_t *der_end, uint64_t *r) {
    size_t der_len;

    if((der = der_decode(DER_INT, der, der_end, &der_len)) != NULL && (*der & 0x80U) == 0 && (der_len <= sizeof(*r) || (--der_len == sizeof(*r) && *der++ == 0))) {
        *r = 0;
        while(der_len-- != 0) {
            *r = (*r << 8U) | *der++;
        }
        return der;
    }
    return NULL;
}

size_t
decompress_lzss(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_len) {
    const uint8_t *src_end = src + src_len, *dst_start = dst, *dst_end = dst + dst_len;
    uint16_t i, r = LZSS_N - LZSS_F, flags = 0;
    uint8_t text_buf[LZSS_N + LZSS_F - 1], j;

    memset(text_buf, ' ', r);
    while(src != src_end && dst != dst_end) {
        if(((flags >>= 1U) & 0x100U) == 0) {
            flags = *src++ | 0xFF00U;
            if(src == src_end) {
                break;
            }
        }
        if((flags & 1U) != 0) {
            text_buf[r++] = *dst++ = *src++;
            r &= LZSS_N - 1U;
        } else {
            i = *src++;
            if(src == src_end) {
                break;
            }
            j = *src++;
            i |= (j & 0xF0U) << 4U;
            j = (j & 0xFU) + LZSS_THRESHOLD;
            do {
                *dst++ = text_buf[r++] = text_buf[i++ & (LZSS_N - 1U)];
                r &= LZSS_N - 1U;
            } while(j-- != 0 && dst != dst_end);
        }
    }
    return (size_t)(dst - dst_start);
}

void *
kdecompress(const void *src, size_t src_len, size_t *dst_len) {
	const uint8_t *der, *octet, *der_end, *src_end = (const uint8_t *)src + src_len;
	struct {
		uint32_t magic, type, adler32, uncomp_sz, comp_sz;
		uint8_t pad[KCOMP_HDR_PAD_SZ];
	} kcomp_hdr;
	size_t der_len;
	uint64_t r;
	void *dst;

	if((der = der_decode_seq(src, src_end, &der_end)) != NULL && (der = der_decode(DER_IA5_STR, der, der_end, &der_len)) != NULL && der_len == 4 && (memcmp(der, "IMG4", der_len) != 0 || ((der = der_decode_seq(der + der_len, src_end, &der_end)) != NULL && (der = der_decode(DER_IA5_STR, der, der_end, &der_len)) != NULL && der_len == 4)) && memcmp(der, "IM4P", der_len) == 0 && (der = der_decode(DER_IA5_STR, der + der_len, der_end, &der_len)) != NULL && der_len == 4 && memcmp(der, "krnl", der_len) == 0 && (der = der_decode(DER_IA5_STR, der + der_len, der_end, &der_len)) != NULL && (der = der_decode(DER_OCTET_STR, der + der_len, der_end, &der_len)) != NULL && der_len > sizeof(kcomp_hdr)) {
		octet = der;
		memcpy(&kcomp_hdr, octet, sizeof(kcomp_hdr));
		if(kcomp_hdr.magic == __builtin_bswap32(KCOMP_HDR_MAGIC)) {
			if(kcomp_hdr.type == __builtin_bswap32(KCOMP_HDR_TYPE_LZSS) && (kcomp_hdr.comp_sz = __builtin_bswap32(kcomp_hdr.comp_sz)) <= der_len - sizeof(kcomp_hdr) && (kcomp_hdr.uncomp_sz = __builtin_bswap32(kcomp_hdr.uncomp_sz)) != 0 && (dst = malloc(kcomp_hdr.uncomp_sz)) != NULL) {
				if(decompress_lzss(octet + sizeof(kcomp_hdr), kcomp_hdr.comp_sz, dst, kcomp_hdr.uncomp_sz) == kcomp_hdr.uncomp_sz) {
					*dst_len = kcomp_hdr.uncomp_sz;
					return dst;
				}
				free(dst);
			}
		} else if((der = der_decode_seq(der + der_len, src_end, &der_end)) != NULL && (der = der_decode_uint64(der, der_end, &r)) != NULL && r == 1 && der_decode_uint64(der, der_end, &r) != NULL && r != 0 && (dst = malloc(r)) != NULL) {
			if(compression_decode_buffer(dst, r, octet, der_len, NULL, COMPRESSION_LZFSE) == r) {
				*dst_len = r;
				return dst;
			}
			free(dst);
		}
	}
	return NULL;
}
