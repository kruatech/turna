# AF_XDP 1.1 — embedded XDP filter: first-build checklist

This change makes `transport = "af_xdp"` self-contained: instead of relying on
libxdp's default "redirect-everything" program (auto-loaded by xsk-rs today), the
datapath attaches an in-tree **selective** XDP program that redirects only UDP
datagrams whose destination port is in a BPF map (`ports`) and `XDP_PASS`es
everything else (ARP, ND, non-TURN traffic) to the kernel. Relay ports are added
to / removed from `ports` dynamically.

It is **Linux-only and was not compiled or run** in the authoring environment
(no NIC, libxdp/libbpf, clang-bpf, or kernel headers there). Verify the points
below on the first `cargo build --features af-xdp` / lab run.

## Files

- `crates/transport/src/bpf/xdp_turn.c` — the XDP program (`xsks_map`, `ports`).
- `crates/transport/build.rs` — compiles the program to `$OUT_DIR/xdp_turn.o`
  under the `af-xdp` feature (no-op otherwise).
- `crates/transport/Cargo.toml` — adds `libxdp-sys` + `libbpf-sys` (already in the
  tree transitively via `xsk-rs`) to the `af-xdp` feature.
- `crates/transport/src/af_xdp.rs` — `xsk::loader` module (all libxdp/libbpf FFI),
  `INHIBIT_PROG_LOAD` + bind-flag wiring in `bind()`, `add_relay_port` /
  `del_relay_port`.
- `services/node/src/af_xdp_listener.rs` — calls add/del relay port on
  Register/Close.

## Build prerequisites (Linux test box)

- `clang` + `llvm` (BPF target) and `linux-libc-dev` (uapi `linux/*.h`).
- `libxdp-sys`/`libbpf-sys` build deps (clang/libclang for bindgen, `cc`,
  elfutils/`libelf`, `zlib`). `bpf/bpf_helpers.h` reaches `build.rs` via
  `DEP_BPF_INCLUDE` (set because `libbpf-sys` is now a direct dep). If the
  `cargo:warning=DEP_BPF_INCLUDE not set` line appears, the header path didn't
  propagate — check the `libbpf-sys` dep resolved.

## Verify in order (most likely to bite first)

1. **libxdp load ordering.** The loader does
   `bpf_object__open_mem` → `xdp_program__from_bpf_obj(obj, NULL)` →
   `xdp_program__attach` and *then* reads map fds, relying on `attach` to load
   the object. If attach fails or `bpf_map__fd` returns `-1`, insert a
   `bpf_object__load(obj)` before `xdp_program__from_bpf_obj`.
2. **Program section name.** `from_bpf_obj(obj, NULL)` auto-selects the single
   `SEC("xdp")` program. If your libxdp rejects NULL, pass
   `b"xdp\0".as_ptr() as *const c_char`.
3. **Zero-copy bind ordering.** With `INHIBIT_PROG_LOAD` we bind the AF_XDP
   socket (xsk-rs `Socket::new`) **before** attaching our program. Some drivers
   require the XDP program attached before a `XDP_ZEROCOPY` bind. If
   `zero_copy = true` fails at `Socket::new`, fall back to `zero_copy = false`
   (SKB/copy) — the safe path for veth and most testing. (DRV attach mode is
   selected by `cfg.zero_copy` per the agreed mapping.)
4. **bindgen signatures.** FFI is written against libxdp 1.6 / libbpf 1.5 C
   prototypes (verified from the vendored headers): `xdp_attach_mode` is a
   `c_uint` alias (NATIVE=1, SKB=2); `*mut`→`*const` pointer coercions are used
   for `find_map_by_name` / `bpf_map__fd`. If bindgen emits different shapes,
   adjust the `use libxdp_sys::…` calls in `xsk::loader`.
5. **ARP behaviour change.** Non-UDP ingress now `XDP_PASS`es to the kernel, so
   the kernel answers ARP/ND for the bound IP again. The in-band
   `maybe_arp_reply` / `maybe_ndp_reply` path in `recv_batch` goes dormant
   (harmless). With `listen = 0.0.0.0` confirm neighbor resolution still works.
6. **Graceful unload.** On datapath drop, `XdpProgram::Drop` detaches and closes
   the program/object. Confirm `ip link show <iface>` shows no leftover
   `prog/xdp` after shutdown.

## Out of scope here (later tasks)

- IPv6 extension-header walk (1.4): IPv6 packets whose next-header isn't UDP are
  passed to the kernel for now.
- Multi-queue / RSS (1.3): one xsk + one `xsks_map` entry (this queue) only.
- `xdp_statistics()` ring counters (`rx_ring_full`, `fill_ring_empty`, …) for 1.6
  are available on `RxQueue::fd()` but not wired yet.
