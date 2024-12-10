// #include <sys/socket.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
// #include <linux/in.h>

#define AF_INET 2
#define AF_INET6 10
#define SOCK_DGRAM 2
#define MAX_IPV6_EXT_NUM 5

/*
 *  NextHeader field of IPv6 header
 */

#define NEXTHDR_HOP 0       /* Hop-by-hop option header. */
#define NEXTHDR_ROUTING 43  /* Routing header. */
#define NEXTHDR_FRAGMENT 44 /* Fragmentation/reassembly header. */
#define NEXTHDR_AUTH 51     /* Authentication header. */
#define NEXTHDR_DEST 60     /* Destination options header. */

#define NEXTHDR_TCP 6    /* TCP segment. */
#define NEXTHDR_UDP 17   /* UDP message. */
#define NEXTHDR_ICMP 58  /* ICMP for IPv6. */
#define NEXTHDR_NONE 59  /* No next header */
#define NEXTHDR_SCTP 132 /* SCTP message. */



struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u16);
	__type(value, __u16);
} sock_in_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u16);
	__type(value, __u16);
} sock_out_map SEC(".maps");


union ipaddr {
	__be32 daddr4;
	struct in6_addr daddr6;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 128);
	__type(key, union ipaddr);
	__type(value, __u8);
} allow_ips SEC(".maps");


#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define ETH_P_IP6 0x86dd /* Internet Protocol packet */


static __always_inline int modify_udp_ingress(struct __sk_buff *skb, __u16 l4_offset, struct udphdr *udphdr )
{
	__u16 dport;
	if (bpf_skb_load_bytes(skb, l4_offset + offsetof(struct udphdr, dest), &dport, sizeof(dport)))
		return TC_ACT_OK;
	dport  = bpf_ntohs(dport);
	__u16 *dst_port = bpf_map_lookup_elem(&sock_in_map, &dport);
	if (dst_port == NULL)
		return TC_ACT_OK;
	u32 type;
	if (bpf_skb_load_bytes(skb, l4_offset + sizeof(struct udphdr), &type, sizeof(type)))
		return TC_ACT_OK;
	if ((type & 0xffffff00) == 0 && (type & 0xff) <= 4)
		return TC_ACT_OK;

//	bpf_printk("redirect ingress udp %d => %d", dport , *dst_port);
	__u16 dst_port_ = bpf_htons(*dst_port);
	bpf_skb_store_bytes(skb, l4_offset + offsetof(struct udphdr, dest), &dst_port_, 2, 0);
	bpf_l4_csum_replace(skb, l4_offset + offsetof(struct udphdr, check), bpf_htons(dport), bpf_htons(*dst_port), 2);
	return TC_ACT_OK;
}
static __always_inline int modify_udp_egress(struct __sk_buff *skb, __u16 l4_offset, struct udphdr *udphdr)
{
	__u16 sport;
	bpf_skb_load_bytes(skb, l4_offset + offsetof(struct udphdr, source), &sport, 2);
	sport  = bpf_ntohs(sport);
	__u16 *dst_port = bpf_map_lookup_elem(&sock_out_map, &sport);
	if (dst_port != NULL) {
		bpf_printk("redirect egress udp %d => %d", sport , *dst_port);
		__u16 dst_port_ = bpf_htons(*dst_port);
		bpf_skb_store_bytes(skb, l4_offset + offsetof(struct udphdr, source), &dst_port_, 2, 0);
		bpf_l4_csum_replace(skb, l4_offset + offsetof(struct udphdr, check), bpf_htons(sport), bpf_htons(*dst_port), 2);
	}
	return TC_ACT_OK;
}

static __always_inline int modify_ip4(struct __sk_buff *skb, struct iphdr *l3, __u8 ingress, void * data_end)
{
	if (l3->protocol != IPPROTO_UDP) {
		return TC_ACT_OK;
	}
	if (l3->version != 4)
		return TC_ACT_OK;
	struct udphdr *udphdr = (void *)((__u8 *)l3 + l3->ihl * 4 );
	if ((void*)(udphdr + 1) > data_end)
		return TC_ACT_OK;
//	bpf_printk("Got IP packet: %pI4 => %pI4:%d", &l3->saddr, &l3->daddr, bpf_ntohs(udphdr->dest));
	
	
	__u16 l4_off = (__u16)((__u64)udphdr- (__u64)skb->data);
	if (ingress) {
		return modify_udp_ingress(skb, l4_off , udphdr);
	}else {
		return modify_udp_egress(skb, l4_off, udphdr );
	}
}
static __always_inline int modify_ip6(struct __sk_buff *skb, struct ipv6hdr *l3, __u8 ingress, void * data_end)
{
	if (l3->version != 6)
		return TC_ACT_OK;
	u16 len = sizeof(struct ipv6hdr);
	u8 nexthdr = l3->nexthdr;
	struct ipv6_opt_hdr opthdr;
#pragma unroll
	for (int i = 0; i < MAX_IPV6_EXT_NUM - 1; i++) {
		switch (nexthdr) {
		case NEXTHDR_AUTH:
		case NEXTHDR_FRAGMENT:
		    return TC_ACT_OK;
		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_DEST: {
		    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + len, &opthdr,
		                           sizeof(opthdr))) {
		        return TC_ACT_SHOT;
		    }
		    len += (opthdr.hdrlen + 1) * 8;
		    nexthdr = opthdr.nexthdr;
		    break;
		}
		default:
		    goto found_upper_layer;
		}
	}
	

found_upper_layer:
	if (nexthdr != NEXTHDR_UDP)
		return TC_ACT_OK;

	struct udphdr *udphdr = (void *)((__u8 *)l3 + len);
	if ((void*)(udphdr + 1) > data_end)
		return TC_ACT_OK;
	// bpf_printk("Got IP packet: %pI6 => %pI6:%d", &l3->saddr, &l3->daddr, bpf_ntohs(udphdr->dest));
	
	
	__u16 l4_off = (__u16)((__u64)udphdr- (__u64)skb->data);
	if (ingress) {
		return modify_udp_ingress(skb, l4_off , udphdr);
	}else {
		return modify_udp_egress(skb, l4_off, udphdr );
	}
}

/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc/ingress")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;
	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	if (ctx->protocol == bpf_htons(ETH_P_IP)){
		l3 = (struct iphdr *)(l2 + 1);
		if ((void *)(l3 + 1) > data_end)
			return TC_ACT_OK;
		
		union ipaddr addr = {0};
		addr.daddr4 = l3->daddr;
		// bpf_printk("Got IP packet: %pI6", &addr.daddr6);
		if (bpf_map_lookup_elem(&allow_ips, &addr) == NULL)
			return TC_ACT_OK;

		return modify_ip4(ctx, l3, 1, data_end);
	}else if (ctx->protocol == bpf_htons(ETH_P_IP6))
	{
		struct ipv6hdr *ip6hdr = (struct ipv6hdr *)(l2 + 1);
		if ((void *)(ip6hdr + 1) > data_end)
			return TC_ACT_OK;
		// union ipaddr addr = {
		// 	.daddr6 = ip6hdr->daddr,
		// };
		// if (bpf_map_lookup_elem(&allow_ips, &addr) == NULL)
		// 	return TC_ACT_OK;
		return modify_ip6(ctx, ip6hdr, 1, data_end);

	}
	
	return TC_ACT_OK;
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;
	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	if (ctx->protocol == bpf_htons(ETH_P_IP)){
		l3 = (struct iphdr *)(l2 + 1);
		if ((void *)(l3 + 1) > data_end)
			return TC_ACT_OK;
		union ipaddr addr = {0};
		addr.daddr4 = l3->saddr;

		if (bpf_map_lookup_elem(&allow_ips, &addr) == NULL)
			return TC_ACT_OK;
//		bpf_printk("Got egress IP packet: %pI4", &addr.daddr4);
		return modify_ip4(ctx, l3, 0, data_end);
	}else if (ctx->protocol == bpf_htons(ETH_P_IP6))
	{
		struct ipv6hdr *ip6hdr = (struct ipv6hdr *)(l2 + 1);
		if ((void *)(ip6hdr + 1) > data_end)
			return TC_ACT_OK;
		union ipaddr addr = {
			.daddr6 = ip6hdr->saddr,
		};
		if (bpf_map_lookup_elem(&allow_ips, &addr) == NULL)
			return TC_ACT_OK;
		return modify_ip6(ctx, ip6hdr, 0, data_end);
	}
	
	return TC_ACT_OK;
}

//char __license[] SEC("license") = "GPL";

char LICENSE[] SEC("license") = "GPL";
