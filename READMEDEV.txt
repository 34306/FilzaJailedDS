# FilzaJailedDS — M1/M2/M3/M4 iPad Fork

Based on the original [FilzaJailedDS](https://github.com/34306/FilzaJailedDS) by 34306.

This fork adds support for **Apple Silicon iPads (M1, M2, M3)** running **iOS/iPadOS 17.0 through 26.0.x**.

---

## What Changed vs. the Original

### 1. `kexploit/offsets.m` — Apple Silicon iPad detection

A new `isAppleSiliconIPad` runtime flag is computed at startup and stored globally.
It is `true` when the device is a **iPad** running an **M1, M2, M3, or M4** chip.

```
M1 = CPUFAMILY_ARM_FIRESTORM_ICESTORM  (shares family with iPhone A14)
M2 = CPUFAMILY_ARM_BLIZZARD_AVALANCHE  (shares family with iPhone A15)
M3 = CPUFAMILY_ARM_IBIZA               (unique to M3, no iPhone equivalent)
M4 = CPUFAMILY_ARM_DONAN               (unique to M4, no iPhone equivalent)
```

Because M1/M2 share CPU families with phones, `isIPad` is used to disambiguate.
M3/M4 have unique families so they are unambiguous, but still need the iPad VA fix.

**VM address space override (inside the iOS 17.0 block, persists for 18.x and 26.x):**

| Device                  | VM_MIN_KERNEL_ADDRESS    | t1sz_boot |
|-------------------------|--------------------------|-----------|
| iPhone (all chips)      | `0xFFFFFFDC00000000`     | `0x19`    |
| M1/M2/M3/M4 iPad        | `0xFFFFFE0000000000`     | `0x16`    |

Apple Silicon iPads use a wider 42-bit kernel virtual address space. Without this
override, `is_kaddr_valid()` rejects valid M1 PCB addresses (e.g. `0xFFFFFE1401308420`)
and the exploit aborts before it starts.

This block is set **once** in the iOS ≥17.0 block. No subsequent version block
(18.0, 18.1, 18.4, 18.6, 26.0) ever resets `VM_MIN_KERNEL_ADDRESS` or `t1sz_boot`,
so the override is automatically effective for **all supported iOS versions**.

---

### 2. `kexploit/offsets.h` — new declarations

- `extern bool gIsAppleSiliconIPad;` — makes the iPad flag available to all files
- `bool is_pac_supported(void);` — declaration for existing function in offsets.m

---

### 3. `sandbox_escape.m` — dynamic PAC stripping and address validation

**Problem with the original code on M1 iPad:**

- `K(x)` used hardcoded `(x) > 0xFFFFFF8000000000` — rejects every valid M1 address
  because M1 kernel addresses start at `0xFFFFFE...`, which is *below* that constant.
- `S(x)` ORed stripped pointers with `0xFFFFFF8000000000` — corrupts M1 addresses.
- `__xpaci_sbx` used XPACI — incorrect for data pointers (ucred, proc_ro are DA-signed).

**Fix — everything is now dynamically dispatched at runtime:**

```
__xpaci_sbx(ptr)
  → if M1+ iPad: uses XPACD (0xDAC147E0) — correct for data pointers
  → if iPhone:   uses XPACI (0xDAC143E0) — original GitHub behaviour

S(ptr)
  → if M1+ iPad: returns stripped value as-is (already canonical 0xFFFFFE...)
  → if iPhone:   applies original sign-extend OR (0xFFFFFF8000000000)

K(ptr)
  → always uses VM_MIN_KERNEL_ADDRESS (set dynamically by offsets_init)
  → iPhone:     ≥ 0xFFFFFFDC00000000
  → M1+ iPad:   ≥ 0xFFFFFE0000000000
```

---


### 4. `kexploit/kexploit_opa334.h`

Added `extern uint64_t rwSocketPcb;` to expose the socket PCB address for
diagnostic logging in `early_kread`.

---

### 5. Logs Imrovements

Added an alert to display logs for Developer to see which part of the code exactly has an error. Logs are also stored in the application Document Directory when Document Browser is turned on

---

## Device & iOS Version Coverage

### Kernel structure offsets — which path each M chip takes

| Chip | CPU Family                        | Offset path in offsets.m                |
|------|-----------------------------------|------------------------------------------|
| M1   | FIRESTORM_ICESTORM (= A14)        | base → **isA13Above** override           |
| M2   | BLIZZARD_AVALANCHE (= A15)        | base → isA13Above → **isA15Above**       |
| M3   | IBIZA (unique)                    | base → isA15Above → **isA17Above**       |
| M4   | DONAN (unique)                    | base → **isA18Above** (exploit aborts — see note) |

M3/M4 don't appear in `isA13Above` because they have their own unique families,
but they ARE included in the later groups (`isA15Above`/`isA17Above`/`isA18Above`).

### VA space fix coverage

| iOS version     | M1 fix applied? | Notes                                       |
|-----------------|-----------------|---------------------------------------------|
| 17.0 – 17.7.x   | Yes ✓           | Tested: M1 iPad iOS 17.6.1                  |
| 18.0 – 18.2.x   | Yes ✓           | Offsets present; exploit may fail on patched kernels |
| 18.3 – 18.3.1   | Yes ✓           | Same note                                   |
| 18.3.2+         | Yes ✓           | Apple patched the opa334 exploit; will abort |
| 18.4 – 18.7.x   | Yes ✓           | Offsets present; depends on kernel patch status |
| 26.0 – 26.0.x   | Yes ✓           | Full 26.x block present                     |


## Added Comments Reference

All comments added :

| File | Location | Comment |
|------|----------|---------|
| `offsets.m` | above `isAppleSiliconIPad` | "M1 shares FIRESTORM_ICESTORM with A14 (iPhone)..." |
| `offsets.m` | inside iOS 17.0 block | "Apple Silicon iPads (M1/M2) use a wider kernel VA space..." |
| `sandbox_escape.m` | `__xpaci_ia` function | "XPACI X0 — strips instruction-pointer auth (used on iPhones/PAC phones)" |
| `sandbox_escape.m` | `__xpacd_da` function | "XPACD X0 — strips data-pointer auth (used on M1+ iPads...)" |
| `sandbox_escape.m` | `__xpaci_sbx` wrapper | "Runtime dispatch: M1+ iPad uses XPACD, everything else uses XPACI" |
| `sandbox_escape.m` | `S()` macro | "On iPhone: after XPACI the upper bits may be zeroed..." / "On M1+ iPad..." |
| `sandbox_escape.m` | `K()` macro | "VM_MIN_KERNEL_ADDRESS is set dynamically by offsets_init()..." |
| `sandbox_escape.m` | Steps 1–8 | `// ── Step N:` section headers throughout the escape function |
| `kexploit_opa334.m` | `physical_oob_read_mo` | "Log every 500 calls so the UI stays alive without flooding" |
| `kexploit_opa334.m` | `physical_oob_read_mo` | "New best — always log this" |
| `kexploit_opa334.m` | `physical_oob_read_mo_with_retry` | "Log every 5 consecutive failures..." |
| `kexploit_opa334.m` | `physical_oob_write_mo` | "Log every 50 write calls" |
| `kexploit_opa334.m` | `early_kread` | "Surface this loud and clear — previously a silent hang" |
| `kexploit_opa334.m` | `early_kread` | "Give the dispatch to the main queue time to paint before we spin" |
| `kexploit_opa334.m` | `find_and_corrupt_socket` | Steps 1–9 section headers |
| `kexploit_opa334.m` | `find_and_corrupt_socket` | "Verify the checksum sentinel (0xffffffffffff) is present" |
| `kexploit_opa334.m` | `kexploit_opa334` | Section headers: Device identification, Primitive establishment, etc. |

---

## Original Repo

https://github.com/34306/FilzaJailedDS
