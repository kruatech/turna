#!/usr/bin/env python3
"""Execute the production XDP filter as host C with mocked BPF map helpers.
This checks selection logic, not kernel verification, attachment or NIC behaviour.
"""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class FilterTests(unittest.TestCase):
    def test_packet_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = pathlib.Path(directory)
            (tmp / 'bpf').mkdir()
            (tmp / 'bpf/bpf_helpers.h').write_text('''
#define SEC(name)
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
void *mock_lookup(void *, const void *);
long mock_redirect(void *, unsigned int, unsigned long);
#define bpf_map_lookup_elem mock_lookup
#define bpf_redirect_map mock_redirect
''')
            source = str(ROOT / 'crates/transport/src/bpf/xdp_turn.c')
            (tmp / 'test.c').write_text(r'''
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include "SOURCE"
static struct local_address configured;
static unsigned char present = 1;
static unsigned char packet[256];
void *mock_lookup(void *map, const void *key) {
    if (map == &local_addr) return &configured;
    if (map == &ports && *(const __u16 *)key == 13478) return &present;
    return 0;
}
long mock_redirect(void *map, unsigned int queue, unsigned long fallback) {
    assert(map == &xsks_map);
    return queue < 2 ? XDP_REDIRECT : fallback;
}
static int run(unsigned int queue, unsigned int len) {
    struct xdp_md ctx = {0};
    assert((uintptr_t)packet <= UINT32_MAX);
    ctx.data = (uintptr_t)packet;
    ctx.data_end = (uintptr_t)(packet + len);
    ctx.rx_queue_index = queue;
    return xdp_turn(&ctx);
}
static void ipv4(void) {
    memset(packet, 0, sizeof(packet));
    struct ethhdr *eth = (void *)packet;
    eth->h_proto = __bpf_htons(ETH_P_IP);
    struct iphdr *ip = (void *)(eth + 1);
    ip->version = 4; ip->ihl = 5; ip->protocol = IPPROTO_UDP;
    unsigned char dst[4] = {192, 0, 2, 1};
    memcpy(&ip->daddr, dst, 4);
    configured.family = 4; memcpy(configured.bytes, dst, 4);
    struct udphdr *udp = (void *)(ip + 1);
    udp->dest = __bpf_htons(13478);
}
int main(void) {
    ipv4(); assert(run(0, 42) == XDP_REDIRECT); assert(run(1, 42) == XDP_REDIRECT);
    assert(run(2, 42) == XDP_PASS);
    assert(run(0, 10) == XDP_PASS);
    struct iphdr *ip = (void *)(packet + 14);
    ip->protocol = IPPROTO_TCP; assert(run(0, 42) == XDP_PASS);
    ipv4(); packet[30] ^= 1; assert(run(0, 42) == XDP_PASS);
    ipv4(); ip->frag_off = __bpf_htons(1); assert(run(0, 42) == XDP_PASS);
    ipv4(); ip->frag_off = __bpf_htons(0x2000); assert(run(0, 42) == XDP_PASS);
    ipv4(); packet[36] = 0; packet[37] = 9; assert(run(0, 42) == XDP_PASS);
    ipv4(); ((struct ethhdr *)packet)->h_proto = __bpf_htons(ETH_P_ARP);
    assert(run(0, 42) == XDP_PASS);
    memset(packet, 0, sizeof(packet));
    ((struct ethhdr *)packet)->h_proto = __bpf_htons(ETH_P_IPV6);
    struct ipv6hdr *ip6 = (void *)(packet + 14);
    ip6->version = 6; ip6->nexthdr = IPPROTO_UDP;
    configured.family = 6; memset(configured.bytes, 0, 16); configured.bytes[15] = 1;
    memcpy(&ip6->daddr, configured.bytes, 16);
    ((struct udphdr *)(ip6 + 1))->dest = __bpf_htons(13478);
    assert(run(1, 62) == XDP_REDIRECT);
    packet[53] = 2; assert(run(1, 62) == XDP_PASS);
    packet[53] = 1; ip6->nexthdr = IPPROTO_ICMPV6; assert(run(1, 62) == XDP_PASS);
    return 0;
}
'''.replace('SOURCE', source))
            subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-pointer-to-int-cast', '-no-pie', '-I', str(tmp), str(tmp / 'test.c'), '-o', str(tmp / 'test')], check=True)
            subprocess.run([str(tmp / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
