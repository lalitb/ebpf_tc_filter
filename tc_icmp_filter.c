#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// Compatibility for kernel/BPF environments
#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif
#define IPPROTO_ICMP 1
#define ICMP_ECHO 8

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2


char LICENSE[] SEC("license") = "GPL";

struct icmphdr {
    __u8 type;
    __u8 code;
    __u16 checksum;
    __u16 id;
    __u16 sequence;
};

SEC("tc")
int hello_tc_prog(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_ICMP)
        return TC_ACT_OK;

    // ICMP header
    struct icmphdr *icmp = (void *)(ip + 1);
    if ((void *)(icmp + 1) > data_end)
        return TC_ACT_OK;
    if (icmp->type == ICMP_ECHO) {
        bpf_printk("ICMP Echo Request (ping) seen by TC eBPF! - Dropping packet\n");
        return TC_ACT_SHOT; // Drop the packet
    }

    return TC_ACT_OK;
}