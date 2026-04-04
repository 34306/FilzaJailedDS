//
//  vnode.h
//  darksword-kexploit-fun
//
//  Created by seo on 3/25/26.
//

#ifndef vnode_h
#define vnode_h

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

uint64_t get_vnode_for_path_by_chdir(const char *path);
uint64_t get_vnode_for_path_by_open(const char *path);
uint64_t get_vnode_by_fd(int fd);
uint64_t vnode_redirect_folder(const char *to, const char *from);
bool vnode_unredirect_folder(const char *folder, uint64_t orig_to_v_data);
bool vnode_redirect_file(const char *to, const char *from, uint64_t* orig_to_vnode, uint64_t* orig_to_v_data);
bool vnode_unredirect_file(uint64_t orig_to_vnode, uint64_t orig_to_v_data);
char* vnode_get_v_name(uint64_t vnode);
uint64_t get_rootvnode(void);
uint64_t vnode_get_child_vnode(uint64_t vnode, const char* child_filename, uint64_t blacklist_vdata);

#endif /* vnode_h */
