//! Tokio-based UDP transport (epoll/kqueue). Works on all platforms.
//!
//! # BPF socket filter (Linux only)
//!
//! On Linux, `bind()` automatically attaches a Classic BPF filter that
//! drops packets which are clearly not STUN or TURN ChannelData *in the
//! kernel*, before they are copied to userspace. This frees us from
//! having to parse every garbage packet that arrives on the public UDP
//! port — useful when the server is exposed to the open Internet and
//! receives scan/probe traffic.
//!
//! The filter is best-effort:
//! - On non-Linux platforms it's a no-op.
//! - On Linux without `CAP_NET_RAW` (e.g. the test process under
//!   `cargo test` without sudo), `setsockopt(SO_ATTACH_FILTER)` returns
//!   `EPERM`. We log a warning and continue without the filter.
//! - Disable explicitly with `TURNA_BPF_FILTER=0` — useful for the
//!   load-test "with vs without filter" comparison.
//!
//! See `crates/transport/src/bpf_filter.rs` for the filter itself.

use crate::{Result, Transport};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Largest STUN/TURN message we accept at all. RFC 8489 caps STUN at
/// 64 KiB minus headers; in practice no real client sends anything
/// close to this. The BPF filter rejects packets longer than this
/// before they reach our parser.
///
/// Lives under `cfg(target_os = "linux")` because the only place it's
/// referenced is the BPF attach path, which itself is Linux-only. On
/// macOS the symbol simply doesn't exist — no dead-code warning.
#[cfg(target_os = "linux")]
const MAX_PACKET_SIZE: u32 = 8192;

/// Shared UDP socket handle — cheaply cloneable.
#[derive(Clone)]
pub struct TokioTransport {
    socket: Arc<UdpSocket>,
}

impl TokioTransport {
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        tracing::info!(%addr, "UDP socket bound (tokio)");

        // Attach the kernel-side STUN/ChannelData filter unless explicitly
        // disabled. We deliberately swallow errors: lack of permission to
        // call `setsockopt(SO_ATTACH_FILTER)` is the typical case under
        // unprivileged dev runs, and it must not prevent the server from
        // starting. The cost is that packets are filtered in userspace
        // instead of in the kernel.
        Self::try_attach_bpf_filter(&socket);

        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
        }
    }

    /// Bind с SO_REUSEPORT, выставленным ДО bind (только Unix).
    /// Несколько таких сокетов на одном порту образуют kernel
    /// load-balancing группу (Linux >= 3.9) — как у coturn.
    /// Linux: принять до `bufs.len()` датаграмм ОДНИМ вызовом recvmmsg.
    /// `out[k] = (len, src)` для каждой принятой. Возвращает их число (>=1).
    #[cfg(target_os = "linux")]
    pub async fn recv_mmsg(
        &self,
        bufs: &mut [&mut [u8]],
        out: &mut [(usize, SocketAddr)],
    ) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd;
        debug_assert!(out.len() >= bufs.len() && !bufs.is_empty());
        let fd = self.socket.as_raw_fd();
        loop {
            self.socket.readable().await?;
            let res = self.socket.try_io(tokio::io::Interest::READABLE, || {
                let n = bufs.len();
                // SAFETY: sockaddr_storage is a C POD type; all-zeroes is a valid value.
                let mut addrs: Vec<libc::sockaddr_storage> = vec![unsafe { std::mem::zeroed() }; n];
                let mut iovecs: Vec<libc::iovec> = bufs
                    .iter_mut()
                    .map(|b| libc::iovec {
                        iov_base: b.as_mut_ptr().cast(),
                        iov_len: b.len(),
                    })
                    .collect();
                let mut hdrs: Vec<libc::mmsghdr> = (0..n)
                    .map(|k| {
                        // SAFETY: libc::mmsghdr is a C POD type; all-zeroes is valid.
                        let mut h: libc::mmsghdr = unsafe { std::mem::zeroed() };
                        h.msg_hdr.msg_iov = &mut iovecs[k];
                        h.msg_hdr.msg_iovlen = 1;
                        h.msg_hdr.msg_name = (&mut addrs[k] as *mut libc::sockaddr_storage).cast();
                        h.msg_hdr.msg_namelen =
                            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                        h
                    })
                    .collect();
                // SAFETY: `fd` is open; `hdrs` is a valid array of `n` initialized
                // mmsghdr; null timeout means block per MSG_DONTWAIT semantics.
                let r = unsafe {
                    libc::recvmmsg(
                        fd,
                        hdrs.as_mut_ptr(),
                        n as libc::c_uint,
                        libc::MSG_DONTWAIT,
                        std::ptr::null_mut(),
                    )
                };
                if r < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let r = r as usize;
                for k in 0..r {
                    // SAFETY: addrs[k] was filled by recvmmsg with msg_namelen bytes,
                    // a valid initialized sockaddr; copied into a socket2 0.6
                    // storage view (SockAddrStorage) before constructing SockAddr.
                    let sa = unsafe {
                        let mut storage = socket2::SockAddrStorage::zeroed();
                        *storage.view_as::<libc::sockaddr_storage>() = addrs[k];
                        socket2::SockAddr::new(storage, hdrs[k].msg_hdr.msg_namelen)
                    };
                    let src = sa.as_socket().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "non-IP source addr")
                    })?;
                    out[k] = (hdrs[k].msg_len as usize, src);
                }
                Ok(r)
            });
            match res {
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Переносимый fallback: один пакет за вызов.
    #[cfg(not(target_os = "linux"))]
    pub async fn recv_mmsg(
        &self,
        bufs: &mut [&mut [u8]],
        out: &mut [(usize, SocketAddr)],
    ) -> std::io::Result<usize> {
        let (n, src) = self.socket.recv_from(bufs[0]).await?;
        out[0] = (n, src);
        Ok(1)
    }

    /// Linux: отправить все пакеты, батчами sendmmsg.
    #[cfg(target_os = "linux")]
    pub async fn send_mmsg(&self, pkts: &[(bytes::Bytes, SocketAddr)]) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        if pkts.is_empty() {
            return Ok(());
        }
        let fd = self.socket.as_raw_fd();
        let mut sent = 0usize;
        while sent < pkts.len() {
            self.socket.writable().await?;
            let res = self.socket.try_io(tokio::io::Interest::WRITABLE, || {
                let batch = &pkts[sent..];
                let n = batch.len();
                let addrs: Vec<socket2::SockAddr> = batch
                    .iter()
                    .map(|(_, a)| socket2::SockAddr::from(*a))
                    .collect();
                let mut iovecs: Vec<libc::iovec> = batch
                    .iter()
                    .map(|(d, _)| libc::iovec {
                        iov_base: d.as_ptr() as *mut _,
                        iov_len: d.len(),
                    })
                    .collect();
                let mut hdrs: Vec<libc::mmsghdr> = (0..n)
                    .map(|k| {
                        // SAFETY: libc::mmsghdr is a C POD type; all-zeroes is valid.
                        let mut h: libc::mmsghdr = unsafe { std::mem::zeroed() };
                        h.msg_hdr.msg_iov = &mut iovecs[k];
                        h.msg_hdr.msg_iovlen = 1;
                        h.msg_hdr.msg_name = addrs[k].as_ptr() as *mut _;
                        h.msg_hdr.msg_namelen = addrs[k].len();
                        h
                    })
                    .collect();
                // SAFETY: `fd` is open; `hdrs` is a valid array of `n` initialized
                // mmsghdr describing buffers that outlive the call.
                let r = unsafe {
                    libc::sendmmsg(fd, hdrs.as_mut_ptr(), n as libc::c_uint, libc::MSG_DONTWAIT)
                };
                if r < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(r as usize)
            });
            match res {
                Ok(n) => sent += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Переносимый fallback: по одному send_to.
    #[cfg(not(target_os = "linux"))]
    pub async fn send_mmsg(&self, pkts: &[(bytes::Bytes, SocketAddr)]) -> std::io::Result<()> {
        for (data, target) in pkts {
            let _ = self.socket.send_to(data, *target).await?;
        }
        Ok(())
    }

    pub async fn bind_reuseport(addr: SocketAddr) -> Result<Self> {
        #[cfg(unix)]
        {
            use socket2::{Domain, Protocol, Socket, Type};
            let domain = if addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_reuse_port(true)?;
            sock.set_nonblocking(true)?;
            sock.bind(&addr.into())?;
            let socket = UdpSocket::from_std(sock.into())?;
            tracing::info!(%addr, "UDP socket bound (tokio, SO_REUSEPORT)");
            Self::try_attach_bpf_filter(&socket);
            Ok(Self {
                socket: Arc::new(socket),
            })
        }
        #[cfg(not(unix))]
        {
            tracing::warn!(%addr, "SO_REUSEPORT недоступен — обычный bind");
            Self::bind(addr).await
        }
    }

    pub fn inner(&self) -> &UdpSocket {
        &self.socket
    }

    /// Attach the BPF filter to the bound socket. Best-effort: any
    /// failure is logged but not propagated.
    ///
    /// Reads `TURNA_BPF_FILTER`:
    /// - unset / "1" / "true" / "yes" / "on": attach (default).
    /// - "0" / "false" / "no" / "off" / anything else falsy: skip.
    fn try_attach_bpf_filter(socket: &UdpSocket) {
        if !bpf_enabled() {
            tracing::info!("BPF socket filter disabled via TURNA_BPF_FILTER");
            return;
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            match crate::bpf_filter::attach_stun_filter(fd, MAX_PACKET_SIZE) {
                Ok(()) => {
                    tracing::info!(
                        fd,
                        max_size = MAX_PACKET_SIZE,
                        "BPF STUN/ChannelData filter attached"
                    );
                }
                Err(e) => {
                    // EPERM is the typical case without CAP_NET_RAW. Other
                    // errors (EINVAL, ENOSYS) point at a kernel mismatch
                    // and deserve a louder warn either way — but never
                    // fatal.
                    tracing::warn!(error = %e,
                        "could not attach BPF filter — server continues without \
                         kernel-side STUN validation. To enable: run with \
                         CAP_NET_RAW or as root. To silence this warning: \
                         set TURNA_BPF_FILTER=0.");
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            // `socket` is unused on non-Linux; reference it to silence the
            // unused-binding lint when this branch compiles.
            let _ = socket;
            tracing::debug!("BPF socket filter only available on Linux — skipping");
        }
    }
}

/// Read `TURNA_BPF_FILTER` and decide whether to attach.
fn bpf_enabled() -> bool {
    match std::env::var("TURNA_BPF_FILTER") {
        Err(_) => true,
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off" | "disabled"
        ),
    }
}

impl Transport for TokioTransport {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (n, addr) = self.socket.recv_from(buf).await?;
        Ok((n, addr))
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        let n = self.socket.send_to(buf, target).await?;
        Ok(n)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All tests that read or write `TURNA_BPF_FILTER`, OR call `bind()`
    /// (which itself reads the env), are funnelled through this one
    /// `#[test]` so they don't race against each other. Each scenario
    /// is its own block with a comment.
    #[tokio::test]
    async fn bpf_env_and_bind_scenarios() {
        // Scenario 1: unset env → default is enabled.
        std::env::remove_var("TURNA_BPF_FILTER");
        assert!(
            bpf_enabled(),
            "unset env must mean attach (the safer / production default)"
        );

        // Scenario 2: every truthy spelling enables.
        for v in ["1", "true", "yes", "on", "TRUE", "On"] {
            std::env::set_var("TURNA_BPF_FILTER", v);
            assert!(bpf_enabled(), "expected enabled for {v:?}");
        }

        // Scenario 3: every falsy spelling disables.
        for v in ["0", "false", "no", "off", "disabled", "OFF", "False"] {
            std::env::set_var("TURNA_BPF_FILTER", v);
            assert!(!bpf_enabled(), "expected disabled for {v:?}");
        }

        // Scenario 4: bind() works with the filter disabled (so the
        // setsockopt path is bypassed, no permission issues).
        std::env::set_var("TURNA_BPF_FILTER", "0");
        let t = TokioTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind must work with TURNA_BPF_FILTER=0");
        let addr = t.local_addr().expect("local_addr after bind must succeed");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_ne!(addr.port(), 0, "OS must have assigned a real port");
        drop(t);

        // Scenario 5: bind() works even when filter attach fails. On
        // unprivileged dev/CI machines without CAP_NET_RAW the
        // setsockopt returns EPERM; on macOS the attach path is a
        // no-op; either way bind() must succeed.
        std::env::remove_var("TURNA_BPF_FILTER");
        let t = TokioTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind to loopback must succeed regardless of filter outcome");
        let _ = t.local_addr().unwrap();
        drop(t);

        // Clean up so any other test in this binary sees a pristine env.
        std::env::remove_var("TURNA_BPF_FILTER");
    }
}
