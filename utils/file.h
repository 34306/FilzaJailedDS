//
//  file.h
//  darksword-kexploit-fun
//
//  Created by seo on 3/29/26.
//

#ifndef file_h
#define file_h

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// xnu-10002.81.5/bsd/sys/vnode_internal.h
#define VISSHADOW       0x008000        /* vnode is a shadow file */
// xnu-10002.81.5/bsd/sys/mount.h
#define MNT_RDONLY      0x00000001      /* read only filesystem */

uint64_t hide_path(const char* path);
uint64_t reveal_path_by_vnode(uint64_t vnode);
uint64_t overwrite_system_file(char* to, char* from);

#endif /* file_h */
