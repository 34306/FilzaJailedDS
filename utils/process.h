//
//  process.h
//  darksword-kexploit-fun
//
//  Created by seo on 3/26/26.
//

#ifndef process_h
#define process_h

#include <stdio.h>
#include <stdint.h>

struct arm_saved_state64
{
  uint64_t x[29];
  uint64_t fp;
  uint64_t lr;
  uint64_t sp;
  uint64_t pc;
  uint32_t cpsr;
  uint32_t aspsr;
  uint64_t far;
  uint32_t esr;
  uint32_t exception;
  uint64_t jophash;
};

int crash_process(const char* name);
int watch_process(const char* name);

int disable_aslr(void);
int enable_aslr(void);

#endif /* process_h */
