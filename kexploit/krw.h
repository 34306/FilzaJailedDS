//
//  krw.m
//  darksword-kexploit-fun
//
//  Created by seo on 3/24/26.
//

#ifndef krw_m
#define krw_m

#import <stdint.h>
#import <stdbool.h>
#import "offsets.h"

#define BIT(b)           (1ULL << (b))
#define ONES(x)          (BIT((x))-1)
#define PTR_MASK         ONES(64-t1sz_boot)
#define PAC_MASK         (~PTR_MASK)
#define SIGN(p)          ((p) & BIT(55))
#define UNSIGN_PTR(p)    (SIGN(p) ? ((p) | PAC_MASK) : ((p) & ~PAC_MASK))

bool is_kaddr_valid(uint64_t addr);
void kreadbuf(uint64_t addr, void *buf, uint64_t len);
void kwritebuf(uint64_t addr, const void *buf, uint64_t len);
uint16_t kread16(uint64_t kaddr);
uint32_t kread32(uint64_t kaddr);
uint64_t kread64(uint64_t kaddr);
void kwrite8(uint64_t kaddr, uint8_t val);
void kwrite16(uint64_t kaddr, uint16_t val);
void kwrite32(uint64_t kaddr, uint32_t val);
void kwrite64(uint64_t kaddr, uint64_t val);
void khexdump(uint64_t addr, size_t size);
uint64_t kread_ptr(uint64_t va);
uint64_t kread_smrptr(uint64_t va);
void kwrite_zone_element(uint64_t dst, const void *src, uint64_t len);

#endif /* krw_m */
