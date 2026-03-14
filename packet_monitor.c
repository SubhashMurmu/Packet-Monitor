#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "packet_monitor.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Dev");
MODULE_DESCRIPTION("Packet Monitor with Filtering Rules");
MODULE_VERSION("1.2");

struct filter_rule {
    __be32 ip;
    int action;
    bool active;
};

struct ip_counter {
    __be32 ip;
    atomic_long_t count;
};

static atomic_long_t stat_total = ATOMIC_LONG_INIT(0);
static atomic_long_t stat_tcp = ATOMIC_LONG_INIT(0);
static atomic_long_t stat_udp = ATOMIC_LONG_INIT(0);
static atomic_long_t stat_icmp = ATOMIC_LONG_INIT(0);
static atomic_long_t stat_other = ATOMIC_LONG_INIT(0);
static atomic_long_t stat_blocked = ATOMIC_LONG_INIT(0);
static atomic_long_t stat_syn = ATOMIC_LONG_INIT(0);
static atomic_long_t stat_bytes_total = ATOMIC_LONG_INIT(0);
static atomic_long_t stat_max_pkt_sz = ATOMIC_LONG_INIT(0);

static atomic_long_t pps_window_count = ATOMIC_LONG_INIT(0);
static unsigned long pps_last_jiffies;
static unsigned long pps_rate;
static spinlock_t pps_lock;

static struct ip_counter top_ips[PM_MAX_TOP_IPS];
static spinlock_t top_ips_lock;

static struct filter_rule filter_rules[PM_MAX_FILTER_RULES];
static int filter_rule_count = 0;
static spinlock_t filter_lock;
static int filter_mode = PM_MODE_BLACKLIST;

static struct nf_hook_ops nf_hook_ops;
static struct proc_dir_entry *proc_stats;
static struct proc_dir_entry *proc_filter;

static void update_top_ip(__be32 ip)
{
    int i, min_idx = 0;
    long min_val;

    spin_lock(&top_ips_lock);
    
    for (i = 0; i < PM_MAX_TOP_IPS; i++) {
        if (top_ips[i].ip == ip) {
            atomic_long_inc(&top_ips[i].count);
            spin_unlock(&top_ips_lock);
            return;
        }
    }

    for (i = 0; i < PM_MAX_TOP_IPS; i++) {
        if (top_ips[i].ip == 0) {
            min_idx = i;
            goto insert;
        }
    }

    min_val = atomic_long_read(&top_ips[0].count);
    for (i = 1; i < PM_MAX_TOP_IPS; i++) {
        long val = atomic_long_read(&top_ips[i].count);
        if (val < min_val) {
            min_val = val;
            min_idx = i;
        }
    }

insert:
    top_ips[min_idx].ip = ip;
    atomic_long_set(&top_ips[min_idx].count, 1);
    spin_unlock(&top_ips_lock);
}

static void update_pps(void)
{
    unsigned long now = jiffies;
    unsigned long elapsed;

    atomic_long_inc(&pps_window_count);

    if (!spin_trylock(&pps_lock))
        return;

    elapsed = now - pps_last_jiffies;
    if (elapsed >= HZ) {
        long count = atomic_long_xchg(&pps_window_count, 0);
        pps_rate = count * HZ / elapsed;
        pps_last_jiffies = now;
    }
    spin_unlock(&pps_lock);
}

static unsigned int apply_filter_rules(__be32 src_ip)
{
    int i;
    bool matched = false;

    spin_lock(&filter_lock);
    for (i = 0; i < PM_MAX_FILTER_RULES; i++) {
        if (!filter_rules[i].active)
            continue;
        if (filter_rules[i].ip == src_ip) {
            matched = true;
            if (filter_rules[i].action == PM_RULE_BLOCK) {
                spin_unlock(&filter_lock);
                atomic_long_inc(&stat_blocked);
                return NF_DROP;
            }
            if (filter_mode == PM_MODE_WHITELIST) {
                spin_unlock(&filter_lock);
                return NF_ACCEPT;
            }
        }
    }
    spin_unlock(&filter_lock);

    if (filter_mode == PM_MODE_WHITELIST && !matched) {
        atomic_long_inc(&stat_blocked);
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static unsigned int pkt_monitor_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr  *iph;
    struct tcphdr *tcph;
    unsigned int pkt_len;
    long cur_max;
    unsigned int verdict;

    if (!skb) return NF_ACCEPT;

    if (skb_headlen(skb) < sizeof(struct iphdr))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || skb_headlen(skb) < iph->ihl * 4) 
        return NF_ACCEPT;

    verdict = apply_filter_rules(iph->saddr);
    if (verdict == NF_DROP) return NF_DROP;

    atomic_long_inc(&stat_total);
    pkt_len = ntohs(iph->tot_len);
    atomic_long_add(pkt_len, &stat_bytes_total);

    cur_max = atomic_long_read(&stat_max_pkt_sz);
    while ((long)pkt_len > cur_max) {
        if (atomic_long_cmpxchg(&stat_max_pkt_sz, cur_max, (long)pkt_len) == cur_max)
            break;
        cur_max = atomic_long_read(&stat_max_pkt_sz);
    }

    switch (iph->protocol) {
    case IPPROTO_TCP:
        atomic_long_inc(&stat_tcp);
        if (skb_headlen(skb) >= iph->ihl * 4 + sizeof(struct tcphdr)) {
            tcph = (struct tcphdr *)((__u8 *)iph + iph->ihl * 4);
            if (tcph->syn && !tcph->ack)
                atomic_long_inc(&stat_syn);
        }
        break;
    case IPPROTO_UDP:
        atomic_long_inc(&stat_udp);
        break;
    case IPPROTO_ICMP:
        atomic_long_inc(&stat_icmp);
        break;
    default:
        atomic_long_inc(&stat_other);
        break;
    }

    update_top_ip(iph->saddr);
    update_pps();

    return NF_ACCEPT;
}

static int stats_show(struct seq_file *m, void *v)
{
    long total = atomic_long_read(&stat_total);
    long tcp = atomic_long_read(&stat_tcp);
    long udp = atomic_long_read(&stat_udp);
    long icmp = atomic_long_read(&stat_icmp);
    long other = atomic_long_read(&stat_other);
    long blocked = atomic_long_read(&stat_blocked);
    long syn = atomic_long_read(&stat_syn);
    long bytes = atomic_long_read(&stat_bytes_total);
    long max_sz = atomic_long_read(&stat_max_pkt_sz);
    long avg_sz = total ? bytes / total : 0;
    unsigned long rate;
    int i;

    spin_lock_bh(&pps_lock);
    rate = pps_rate;
    spin_unlock_bh(&pps_lock);

    seq_printf(m, "Total Packets   : %ld\n", total);
    seq_printf(m, "TCP  Packets    : %ld\n", tcp);
    seq_printf(m, "UDP  Packets    : %ld\n", udp);
    seq_printf(m, "ICMP Packets    : %ld\n", icmp);
    seq_printf(m, "Other Packets   : %ld\n", other);
    seq_printf(m, "Blocked Packets : %ld\n", blocked);
    seq_printf(m, "SYN  Packets    : %ld\n", syn);
    seq_printf(m, "Total Bytes     : %ld\n", bytes);
    seq_printf(m, "Avg Packet Size : %ld bytes\n", avg_sz);
    seq_printf(m, "Max Packet Size : %ld bytes\n", max_sz);
    seq_printf(m, "Packets / sec   : %lu\n\n", rate);

    spin_lock_bh(&top_ips_lock);
    for (i = 0; i < PM_MAX_TOP_IPS; i++) {
        if (top_ips[i].ip) {
            seq_printf(m, "IP: %pI4    Pkts: %ld\n", &top_ips[i].ip, atomic_long_read(&top_ips[i].count));
        }
    }
    spin_unlock_bh(&top_ips_lock);

    return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, stats_show, NULL);
}

static const struct proc_ops stats_proc_ops = {
    .proc_open = stats_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int filter_show(struct seq_file *m, void *v)
{
    int i;
    seq_printf(m, "Mode: %s\n", filter_mode == PM_MODE_BLACKLIST ? "BLACKLIST" : "WHITELIST");

    spin_lock_bh(&filter_lock);
    for (i = 0; i < PM_MAX_FILTER_RULES; i++) {
        if (filter_rules[i].active) {
            seq_printf(m, "[%s] %pI4\n", filter_rules[i].action == PM_RULE_BLOCK ? "BLOCK" : "ALLOW", &filter_rules[i].ip);
        }
    }
    spin_unlock_bh(&filter_lock);

    return 0;
}

static int filter_open(struct inode *inode, struct file *file)
{
    return single_open(file, filter_show, NULL);
}

static ssize_t filter_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
    char buf[PM_FILTER_BUF_SZ];
    char cmd[16], arg[64], sub[32];
    size_t len;
    __be32 ip;
    u8 parsed_ip[4];
    int i, free_slot, action;

    len = min(count, (size_t)(PM_FILTER_BUF_SZ - 1));
    if (copy_from_user(buf, ubuf, len)) return -EFAULT;
    buf[len] = '\0';

    if (len > 0 && buf[len - 1] == '\n') buf[--len] = '\0';
    if (sscanf(buf, "%15s %63s", cmd, arg) < 1) return -EINVAL;

    if (strcmp(cmd, "clear") == 0) {
        spin_lock_bh(&filter_lock);
        memset(filter_rules, 0, sizeof(filter_rules));
        filter_rule_count = 0;
        spin_unlock_bh(&filter_lock);
        return count;
    }

    if (strcmp(cmd, "mode") == 0) {
        if (sscanf(buf, "%*s %31s", sub) == 1) {
            spin_lock_bh(&filter_lock);
            filter_mode = (strcmp(sub, "whitelist") == 0) ? PM_MODE_WHITELIST : PM_MODE_BLACKLIST;
            spin_unlock_bh(&filter_lock);
        }
        return count;
    }

    if (strcmp(cmd, "block") == 0) action = PM_RULE_BLOCK;
    else if (strcmp(cmd, "allow") == 0) action = PM_RULE_ALLOW;
    else if (strcmp(cmd, "remove") == 0) action = -1;
    else return -EINVAL;

    if (in4_pton(arg, -1, parsed_ip, -1, NULL) == 0) return -EINVAL;
    ip = *(__be32 *)parsed_ip;

    spin_lock_bh(&filter_lock);
    if (action == -1) {
        for (i = 0; i < PM_MAX_FILTER_RULES; i++) {
            if (filter_rules[i].active && filter_rules[i].ip == ip) {
                filter_rules[i].active = false;
                filter_rule_count--;
                break;
            }
        }
    } else {
        free_slot = -1;
        for (i = 0; i < PM_MAX_FILTER_RULES; i++) {
            if (filter_rules[i].active && filter_rules[i].ip == ip) {
                filter_rules[i].action = action;
                spin_unlock_bh(&filter_lock);
                return count;
            }
            if (!filter_rules[i].active && free_slot < 0) free_slot = i;
        }
        if (free_slot >= 0) {
            filter_rules[free_slot].ip = ip;
            filter_rules[free_slot].action = action;
            filter_rules[free_slot].active = true;
            filter_rule_count++;
        }
    }
    spin_unlock_bh(&filter_lock);
    return count;
}

static const struct proc_ops filter_proc_ops = {
    .proc_open = filter_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
    .proc_write = filter_write,
};

static int __init pkt_monitor_init(void)
{
    spin_lock_init(&pps_lock);
    spin_lock_init(&top_ips_lock);
    spin_lock_init(&filter_lock);
    pps_last_jiffies = jiffies;

    nf_hook_ops.hook = pkt_monitor_hook;
    nf_hook_ops.pf = PF_INET;
    nf_hook_ops.hooknum = NF_INET_PRE_ROUTING;
    nf_hook_ops.priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, &nf_hook_ops)) return -ENOMEM;

    proc_stats = proc_create(PM_PROC_STATS, 0444, NULL, &stats_proc_ops);
    if (!proc_stats) {
        nf_unregister_net_hook(&init_net, &nf_hook_ops);
        return -ENOMEM;
    }

    proc_filter = proc_create(PM_PROC_FILTER, 0644, NULL, &filter_proc_ops);
    if (!proc_filter) {
        proc_remove(proc_stats);
        nf_unregister_net_hook(&init_net, &nf_hook_ops);
        return -ENOMEM;
    }
    return 0;
}

static void __exit pkt_monitor_exit(void)
{
    proc_remove(proc_filter);
    proc_remove(proc_stats);
    nf_unregister_net_hook(&init_net, &nf_hook_ops);
}

module_init(pkt_monitor_init);
module_exit(pkt_monitor_exit);
