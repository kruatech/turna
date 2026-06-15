// SPDX-License-Identifier: GPL-2.0
//
// turna AF_XDP filter program (task 1.1 / G2).
//
// Replaces libxdp's default "redirect everything on the queue" program with a
// selective one: only UDP datagrams whose destination port is present in the
// `ports` map are redirected into the AF_XDP socket bound to this queue; all
// other traffic (ARP, ICMP, non-TURN UDP, TCP, …) is XDP_PASS'd back to the
// kernel stack. Userspace seeds `ports` with the main TURN port at attach time
// and adds/removes allocation relay ports dynamically (XskDatapath::set_port).
//
// Built by crates/transport/build.rs with:
//   clang -O2 -g -target bpf -c -I$DEP_BPF_INCLUDE xdp_turn.c -o $OUT_DIR/xdp_turn.o
// and embedded via include_bytes! in af_xdp.rs (loader module).
//
// IPv6 extension headers are not walked here (task 1.4) — an IPv6 packet whose
// next-header is not UDP is passed to the kernel, which is the safe default.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#ifndef __bpf_htons
#define __bpf_htons(x) __builtin_bswap16(x)
#endif

// Per-queue XSK redirect map. Keyed by rx_queue_index; userspace inserts the
// AF_XDP socket fd for the bound queue.
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// Destination UDP ports to redirect (host byte order). value is a presence flag.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u16);
    __type(value, __u8);
} ports SEC(".maps");

SEC("xdp")
int xdp_turn(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 dport_be;

    if (eth->h_proto == __bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        if (ip->protocol != IPPROTO_UDP)
            return XDP_PASS;
        __u32 ihl = (__u32)ip->ihl * 4;
        if (ihl < sizeof(struct iphdr))
            return XDP_PASS;
        struct udphdr *udp = (void *)ip + ihl;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        dport_be = udp->dest;
    } else if (eth->h_proto == __bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        // No extension-header walk yet (task 1.4): only plain UDP is accelerated.
        if (ip6->nexthdr != IPPROTO_UDP)
            return XDP_PASS;
        struct udphdr *udp = (void *)(ip6 + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        dport_be = udp->dest;
    } else {
        return XDP_PASS; // ARP / IPv6 ND / everything else -> kernel
    }

    __u16 key = (__u16)((dport_be >> 8) | (dport_be << 8)); // ntohs
    __u8 *hit = bpf_map_lookup_elem(&ports, &key);
    if (!hit)
        return XDP_PASS;

    // Redirect to the xsk for this queue; if no socket is bound there, the
    // flags arg (XDP_PASS) is the fallback action so traffic still reaches the
    // kernel rather than being dropped.
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
