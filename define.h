#include <linux/version.h>

#if defined(CONFIG_X86_64) && LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
    #define FTRACE_REGS_SYSCALL_STUBS 1
#elif defined(CONFIG_X86_64) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    #define PTREGS_SYSCALL_STUBS 1
#else
    #define LEGACY_SYSCALL_STUBS 1
#endif

#if defined(PTREGS_SYSCALL_STUBS) || defined(FTRACE_REGS_SYSCALL_STUBS)
    #define SYSCALL_NAME(name) ("__x64_" name)
#else
    #define SYSCALL_NAME(name) (name)
#endif

#ifndef FTRACE_OPS_FL_RECURSION_SAFE
#define FTRACE_OPS_FL_RECURSION_SAFE (1 << 4)
#endif
