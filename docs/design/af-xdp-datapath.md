# AF_XDP datapath

Status: **supported within the verified Linux IPv4 UDP copy-mode scope**.
[Evidence and limitations](../verification/af-xdp-supported-2026-09-22.md); native and SKB
copy-mode results do not establish zero-copy or IPv6 WAN support.
The active runtime is `services/node/src/af_xdp_listener.rs` with
`turna_transport::af_xdp::xsk::XskDatapath`. The older hand-written socket wrapper
is not selected by the node. AF_XDP is never auto-selected.

The listener polls one XSK per configured RX queue. Each socket owns an independent
UMEM and rings; all sockets share one embedded address/port-selective XDP program
and its maps. Every enumerated RX queue must be covered, rather than allowing
unhandled TURN flows to fall through to unread kernel sockets. The shared program
is detached when its last owner is dropped.

RX scratch only stores descriptors returned by the ring. A separate pending list
owns descriptors not yet accepted by FILL, surviving subsequent scratch overwrite.
TX-full returns an unsubmitted frame to the free pool. Submission/wakeup failures
are fatal because publication may already have occurred; uncertain frames must
never be reused. Completion returns ownership, not proof of peer delivery.

One loop processes actions, manages relay-map registration and held kernel port
reservations, and periodically reaps allocations/reconciles stale ports. Registration
failure rolls back the allocation and stops before sending a success response.
Readiness is published after socket/filter initialization, not before binding.

The filter passes unrelated addresses/ports, TCP, ARP/NDP and unsupported packet
forms to the kernel. Userspace validates IP/UDP lengths and checksums. Supported
packet forms for this path are unfragmented plain IPv4/IPv6 UDP, single-stack to
the configured concrete listen address. VLAN, IPv6 extension-header acceleration
and fragmentation/reassembly are outside this patch.

Native/SKB attach selection is independent of copy/zero-copy bind selection.
Kernel socket options confirm the requested copy mode. No fallback is represented
as a successful native/zero-copy test. Neighbor resolution is asynchronous and
scoped to the configured interface, with bounded caches and periodic eviction;
static/default gateway MAC fallback still applies during a cache miss.

See [operations](../runbooks/af-xdp.md) and
[changes, tests and remaining gates](../verification/af-xdp-hardening-2026-09-19.md).
