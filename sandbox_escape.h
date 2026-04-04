#ifndef sandbox_escape_h
#define sandbox_escape_h

#include <stdint.h>

// Escape sandbox by rewriting sandbox extension data in kernel memory.
// Walk: proc_ro -> ucred -> cr_label -> sandbox -> ext_set -> ext_table -> ext -> data
// Uses dynamic offset resolution — works on iOS 17.0 through 26.x.
// Returns 0 on success, -1 on failure.
int sandbox_escape(uint64_t self_proc);

#endif
