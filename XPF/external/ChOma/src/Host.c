#include "Host.h"

#include "MachO.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/machine.h>
#include <sys/utsname.h>

int host_get_cpu_information(cpu_type_t *cputype, cpu_subtype_t *cpusubtype)
{
    size_t len;
    
    // Query for cputype
    len = sizeof(cputype);
    if (sysctlbyname("hw.cputype", cputype, &len, NULL, 0) == -1) { printf("Error: no cputype.\n"); return -1; }
    
    // Query for cpusubtype
    len = sizeof(cpusubtype);
    if (sysctlbyname("hw.cpusubtype", cpusubtype, &len, NULL, 0) == -1) { printf("Error: no cpusubtype.\n"); return -1; }
    
    return 0;
}

int host_supported_arm64e_abi(void)
{
    struct utsname name;
    if (uname(&name) != 0) return -1;
    if (strcmp(name.release, "20.0.0") >= 0) {
        // iOS 14+, macOS 11+ use new ABI
        return 2;
    }
    else {
        // iOS 12-13 use old ABI
        return 1;
    }
}

MachO *fat_find_preferred_slice(Fat *fat)
{
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    if (host_get_cpu_information(&cputype, &cpusubtype) != 0) { return NULL; }

    MachO *preferredMacho = NULL;

    // If you intend on supporting non darwin, implement platform specific logic here using #ifdef's
    if (cputype == CPU_TYPE_ARM64) {
        if (cpusubtype == CPU_SUBTYPE_ARM64E) {
            // If this is an arm64e device, first try to find a new ABI arm64e slice
            int supportedArm64eABI = host_supported_arm64e_abi();
            if (supportedArm64eABI != -1) {
                if (supportedArm64eABI == 2) {
                    // Find new ABI slice if host supports it
                    preferredMacho = fat_find_slice(fat, cputype, (CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2));
                }
                if (!preferredMacho) {
                    // If no new ABI slice is found or the host does not support it, try to find an old ABI arm64e slice
                    preferredMacho = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64E);
                    if (preferredMacho) {
                        if (macho_get_filetype(preferredMacho) == MH_EXECUTE && supportedArm64eABI == 2) {
                            // If this is an old ABI binary trying to run on a new ABI system, discard it
                            // If it's an old ABI *library* trying to be loaded on a new ABI system, use it
                            preferredMacho = NULL;
                        }
                    }
                }
            }
        }

        if (!preferredMacho) {
            // If not arm64e device or no arm64e slice found, try to find regular arm64 slice

            // The Kernel prefers an arm64v8 slice to an arm64 slice, so check that first
            // On iOS <14, dyld does not support arm64v8 slices, but that doesn't matter as the Kernel will still try to spawn it
            preferredMacho = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_V8);
            if (!preferredMacho) {
                // If that's not found, finally check for a regular arm64 slice
                preferredMacho = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_ALL);
            }
        }
    }

    if (!preferredMacho) {
        printf("Error: failed to find a preferred MachO slice that matches the host architecture.\n");
    }
    return preferredMacho;
}