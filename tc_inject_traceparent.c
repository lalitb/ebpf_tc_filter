#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

#define TRACEPARENT_HEADER "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n"
#define TRACEPARENT_HEADER_LEN (sizeof(TRACEPARENT_HEADER) - 1)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} target_cgroup SEC(".maps");

static __always_inline int in_target_cgroup(struct __sk_buff *skb) {
    __u32 key = 0;
    __u64 *target = bpf_map_lookup_elem(&target_cgroup, &key);
    if (!target)
        return 0;
    return bpf_skb_cgroup_id(skb) == *target;
}

SEC("tc")
int inject_traceparent(struct __sk_buff *skb) {
    //if (!in_target_cgroup(skb))
    //    return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Ethernet
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;
    struct ethhdr *eth = data;

    // IP
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    int ip_hdr_len = ip->ihl * 4;
    if ((void*)ip + ip_hdr_len > data_end)
        return TC_ACT_OK;

    // TCP
    struct tcphdr *tcp = (void*)ip + ip_hdr_len;
    if ((void*)(tcp + 1) > data_end)
        return TC_ACT_OK;
    // Check if the source port is 8080 (network byte order)
    if (tcp->source != bpf_htons(8080))
        return TC_ACT_OK;

    bpf_printk("------> tc: Got TCP port 8080\n");
    __u8 flags = ((__u8 *)tcp)[13]; // Offset 13 in the TCP header contains the flags (on most architectures)
    bpf_printk("TCP Flags detail: FIN=%d SYN=%d RST=%d PSH=%d ACK=%d URG=%d",
        !!(flags & 0x01), !!(flags & 0x02), !!(flags & 0x04), 
        !!(flags & 0x08), !!(flags & 0x10), !!(flags & 0x20));
            
    // Check specific flag combinations (e.g., SYN+ACK)
    if (flags & (1 << 1) && flags & (1 << 4)) { // SYN is bit 1, ACK is bit 4
        bpf_printk("tc: This is a SYN+ACK packet\n");
    }
    int tcp_hdr_len = tcp->doff * 4;
    if ((void*)tcp + tcp_hdr_len > data_end)
        return TC_ACT_OK;
    bpf_printk("handle-1\n");
    int l4_offset = sizeof(*eth) + ip_hdr_len + tcp_hdr_len;
    bpf_printk("l4_offset: %d, ip_hdr_len: %d, tcp_hdr_len: %d\n", l4_offset, ip_hdr_len, tcp_hdr_len);

    int payload_len = (__u8 *)data_end - (__u8 *)(data + l4_offset);
    bpf_printk("Payload length: %d\n", payload_len);
    // HTTP payload start check
    if (data + l4_offset + 4 > data_end) {
        bpf_printk("HTTP payload too small, exiting\n");
        return TC_ACT_OK;
    }
    __u8 *payload = data + l4_offset;
    // HTTP method check
    if (!(payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P')) {
        bpf_printk("Not an HTTP response, exiting\n");
        return TC_ACT_OK;
    }

    // Find end of HTTP request line (\r\n)
    int req_line_end = -1;
    #pragma unroll
    for (int i = 0; i < 128; i++) {
        void *p = data + l4_offset + i;
        void *p1 = data + l4_offset + i + 1;
        if (p1 >= data_end)
            break;
        if (*(unsigned char *)p == '\r' && *(unsigned char *)p1 == '\n') {
            req_line_end = i + 2;
            break;
        }
    }
    if (req_line_end < 0)
        return TC_ACT_OK;

    // Adjust packet room for header injection
    if (bpf_skb_adjust_room(skb, TRACEPARENT_HEADER_LEN, BPF_ADJ_ROOM_NET, 0))
        return TC_ACT_OK;

    // Re-parse everything after potential packet move
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    // Ethernet
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;
    eth = data;

    // IP
    ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    ip_hdr_len = ip->ihl * 4;
    if ((void*)ip + ip_hdr_len > data_end)
        return TC_ACT_OK;

    // TCP
    tcp = (void*)ip + ip_hdr_len;
    if ((void*)(tcp + 1) > data_end)
        return TC_ACT_OK;
    tcp_hdr_len = tcp->doff * 4;
    if ((void*)tcp + tcp_hdr_len > data_end)
        return TC_ACT_OK;

    l4_offset = sizeof(*eth) + ip_hdr_len + tcp_hdr_len;

    // Final bounds check for injection
    if (data + l4_offset + req_line_end + TRACEPARENT_HEADER_LEN > data_end)
        return TC_ACT_OK;

    // Inject header
    if (bpf_skb_store_bytes(skb, l4_offset + req_line_end,
                            TRACEPARENT_HEADER, TRACEPARENT_HEADER_LEN, 0))
        return TC_ACT_OK;

    // Re-parse IP header before updating fields (for verifier)
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;
    eth = data;
    ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Update IP total length
    __u16 old_len = bpf_ntohs(ip->tot_len);
    __u16 new_len = old_len + TRACEPARENT_HEADER_LEN;
    new_len = bpf_htons(new_len);
    if (bpf_skb_store_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, tot_len),
                            &new_len, sizeof(new_len), 0))
        return TC_ACT_OK;

    // Reset/update IP checksum
    __u16 zero = 0;
    if (bpf_skb_store_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, check),
                            &zero, sizeof(zero), 0))
        return TC_ACT_OK;
    bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), 0, 0, 0);

    // Reset/update TCP checksum
    bpf_l4_csum_replace(skb, sizeof(*eth) + ip_hdr_len + offsetof(struct tcphdr, check),
                        0, 0, BPF_F_PSEUDO_HDR);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";