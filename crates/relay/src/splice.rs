//! splice(2) zero-copy bidirectional TCP relay.
//!
//! For TURN TCP relay (RFC 6062): data passes client↔peer through
//! a pipe in kernel, CPU never touches the bytes.
//!
//! Architecture:
//!   client_fd → splice → pipe_fd → splice → peer_fd
//!   peer_fd   → splice → pipe_fd → splice → client_fd
//!
//! Backpressure (H1 / L4): a slow or stalled destination makes the
//! `pipe → dst` splice return `EAGAIN`. The previous implementation retried
//! with a bare `continue`, which pinned the `spawn_blocking` worker at 100%
//! CPU — a remotely-triggerable self-DoS, since TCP backpressure is normal
//! per RFC 6062. It also `break`-ed on a short write, silently dropping the
//! still-buffered bytes and skewing `SpliceStats`.
//!
//! This version is a small epoll state machine. Each direction keeps the
//! bytes it has pulled from `src` buffered in its pipe (`pending`), and the
//! destination fd is armed with `EPOLLOUT` only while there is something to
//! flush. `epoll_wait` then *blocks* until the destination is writable again
//! instead of spinning. The read side of a direction is armed with `EPOLLIN`
//! only while its pipe has room, so a full pipe never spins on a readable
//! source either. Buffered bytes are always fully accounted for, so no bytes
//! or counters are lost at a backpressure boundary.
//!
//! Falls back to read/write on non-Linux or when splice fails.

#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::RawFd;

use tracing::info;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Pipe buffer size for splice (default: 1 MiB).
const PIPE_SIZE: usize = 1024 * 1024;

/// Max bytes per `src → pipe` splice call.
const SPLICE_MAX: usize = 65536;

/// `epoll_wait` timeout. On expiry the loop simply re-evaluates interest and
/// waits again — it bounds how long an otherwise-idle relay sleeps between
/// shutdown checks; it is *not* a busy-loop (the thread is blocked meanwhile).
const EPOLL_TIMEOUT_MS: libc::c_int = 1000;

const SPLICE_FLAGS: libc::c_uint = libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE;

const EV_IN: u32 = libc::EPOLLIN as u32;
const EV_OUT: u32 = libc::EPOLLOUT as u32;
const EV_HUP: u32 = (libc::EPOLLHUP | libc::EPOLLERR) as u32;

// Per-fd epoll tags.
const TAG_CLIENT: u64 = 0;
const TAG_PEER: u64 = 1;

// ---------------------------------------------------------------------------
// Splice Pipe
// ---------------------------------------------------------------------------

/// A pipe used as intermediate buffer for splice(2).
struct SplicePipe {
    read_fd: RawFd,
    write_fd: RawFd,
    /// Actual kernel pipe capacity in bytes. `F_SETPIPE_SZ` may be clamped by
    /// `/proc/sys/fs/pipe-max-size`, so we read the granted size back rather
    /// than assume `PIPE_SIZE`. Used to gate the read side: we only arm
    /// `EPOLLIN` while `pending < capacity`, otherwise a readable source whose
    /// data cannot fit would re-fire `EPOLLIN` forever (a busy-loop).
    capacity: usize,
}

impl SplicePipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0i32; 2];
        // SAFETY: `fds` is a valid [c_int; 2] the kernel fills; flags are valid.
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Request a larger pipe buffer, then read back the size the kernel
        // actually granted.
        // SAFETY: `fds[0]` is the open read end just created; fcntl F_SETPIPE_SZ/
        // F_GETPIPE_SZ take scalar args only.
        let capacity = unsafe {
            libc::fcntl(fds[0], libc::F_SETPIPE_SZ, PIPE_SIZE as libc::c_int);
            let got = libc::fcntl(fds[0], libc::F_GETPIPE_SZ);
            if got > 0 {
                got as usize
            } else {
                PIPE_SIZE
            }
        };

        Ok(Self {
            read_fd: fds[0],
            write_fd: fds[1],
            capacity,
        })
    }
}

impl Drop for SplicePipe {
    fn drop(&mut self) {
        // SAFETY: read_fd/write_fd are the pipe ends owned here, each closed once in Drop.
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

// ---------------------------------------------------------------------------
// One relay direction (src → pipe → dst)
// ---------------------------------------------------------------------------

/// State for a single direction of the relay. `src`/`dst` are borrowed raw fds
/// (owned by the caller); the pipe is owned here.
struct Direction {
    src: RawFd,
    dst: RawFd,
    pipe: SplicePipe,
    /// Bytes currently buffered in the pipe, waiting to be spliced to `dst`.
    pending: usize,
    /// `src` has returned EOF; no more reads from it.
    src_eof: bool,
    /// We have shut down the write side of `dst` to propagate `src`'s EOF.
    eof_propagated: bool,
    /// Bytes successfully delivered to `dst` (used for stats — counted on
    /// write, so it never over-reports buffered-but-undelivered bytes).
    relayed: u64,
}

impl Direction {
    fn new(src: RawFd, dst: RawFd, pipe: SplicePipe) -> Self {
        Self {
            src,
            dst,
            pipe,
            pending: 0,
            src_eof: false,
            eof_propagated: false,
            relayed: 0,
        }
    }

    /// Fully done: source closed and everything it sent has been delivered.
    fn done(&self) -> bool {
        self.src_eof && self.pending == 0
    }

    /// Should `EPOLLIN` be armed on `src`? Only while we may still read *and*
    /// the pipe has room for more bytes.
    fn want_read(&self) -> bool {
        !self.src_eof && self.pending < self.pipe.capacity
    }

    /// Should `EPOLLOUT` be armed on `dst`? Only while bytes are buffered.
    fn want_write(&self) -> bool {
        self.pending > 0
    }

    /// `src → pipe`. Non-blocking; updates `pending`/`src_eof`. `EAGAIN`
    /// (source empty or pipe full) is not an error.
    fn pump_read(&mut self, splice_calls: &mut u64) -> io::Result<()> {
        if !self.want_read() {
            return Ok(());
        }
        // SAFETY: `self.src` and the pipe write end are open fds owned here; null
        // offsets mean current position, valid for sockets/pipes.
        let n = unsafe {
            libc::splice(
                self.src,
                std::ptr::null_mut(),
                self.pipe.write_fd,
                std::ptr::null_mut(),
                SPLICE_MAX,
                SPLICE_FLAGS,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            return if err.raw_os_error() == Some(libc::EAGAIN) {
                Ok(())
            } else {
                Err(err)
            };
        }
        if n == 0 {
            self.src_eof = true;
            return Ok(());
        }
        self.pending += n as usize;
        *splice_calls += 1;
        Ok(())
    }

    /// `pipe → dst`. Drains as much buffered data as `dst` will currently
    /// accept. On `EAGAIN` the bytes stay buffered and we return so the caller
    /// can wait for `EPOLLOUT` — no busy-loop, no byte loss.
    fn pump_write(&mut self, splice_calls: &mut u64) -> io::Result<()> {
        while self.pending > 0 {
            // SAFETY: the pipe read end and `self.dst` are open fds owned here; null
            // offsets are valid for pipes/sockets.
            let n = unsafe {
                libc::splice(
                    self.pipe.read_fd,
                    std::ptr::null_mut(),
                    self.dst,
                    std::ptr::null_mut(),
                    self.pending,
                    SPLICE_FLAGS,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                return if err.raw_os_error() == Some(libc::EAGAIN) {
                    // Destination send buffer full — leave `pending` intact and
                    // wait for it to become writable (EPOLLOUT).
                    Ok(())
                } else {
                    Err(err)
                };
            }
            if n == 0 {
                // Data is buffered but the destination accepted nothing and did
                // not signal EAGAIN: treat as a broken destination rather than
                // silently dropping the buffered bytes (the L4 drift bug).
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "splice pipe→dst returned 0 with data still buffered",
                ));
            }
            self.pending -= n as usize;
            self.relayed += n as u64;
            *splice_calls += 1;
        }
        Ok(())
    }

    /// Once the source is closed and the pipe is drained, propagate EOF by
    /// shutting down the write half of `dst` (half-close). Idempotent.
    fn maybe_propagate_eof(&mut self) {
        if self.done() && !self.eof_propagated {
            // SAFETY: `self.dst` is the open destination socket owned here.
            unsafe {
                libc::shutdown(self.dst, libc::SHUT_WR);
            }
            self.eof_propagated = true;
        }
    }
}

// ---------------------------------------------------------------------------
// Bidirectional Relay
// ---------------------------------------------------------------------------

/// Stats for a splice relay session.
#[derive(Debug, Clone, Default)]
pub struct SpliceStats {
    pub client_to_peer_bytes: u64,
    pub peer_to_client_bytes: u64,
    pub splice_calls: u64,
    pub fallback_copies: u64,
}

/// Run bidirectional splice relay between two TCP file descriptors.
///
/// This is the zero-copy replacement for `bidirectional_relay()` in tcp_relay.rs.
/// Runs until both sides close or an error occurs.
///
/// For tokio integration: call from spawn_blocking or use epoll to detect
/// readability before each splice call.
pub async fn splice_relay(client_fd: RawFd, peer_fd: RawFd) -> io::Result<SpliceStats> {
    let pipe_c2p = SplicePipe::new()?;
    let pipe_p2c = SplicePipe::new()?;

    info!("splice relay started");

    // Use tokio::task::spawn_blocking because the epoll/splice loop blocks.
    tokio::task::spawn_blocking(move || {
        // NEEDS-REVIEW: client_fd / peer_fd are RawFd (Copy) moved into a
        // spawn_blocking closure. If a sibling async task closes the
        // underlying socket during the blocking loop, the kernel returns
        // EBADF/EPOLLHUP — handled. But ownership is unclear: nothing in the
        // type system guarantees the original socket outlives this task.
        // SAFETY: epoll_create1 takes scalar flags only; the returned fd is checked.
        let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epfd < 0 {
            return Err(io::Error::last_os_error());
        }
        let _epoll_guard = EpollGuard(epfd);

        // client→peer reads from client, writes to peer.
        // peer→client reads from peer, writes to client.
        let mut c2p = Direction::new(client_fd, peer_fd, pipe_c2p);
        let mut p2c = Direction::new(peer_fd, client_fd, pipe_p2c);

        // Initial interest: both sources readable, no pending writes yet.
        let mut client_interest = EV_IN;
        let mut peer_interest = EV_IN;
        epoll_add(epfd, client_fd, client_interest, TAG_CLIENT)?;
        epoll_add(epfd, peer_fd, peer_interest, TAG_PEER)?;

        let mut stats = SpliceStats::default();
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 2];

        while !(c2p.done() && p2c.done()) {
            // Re-arm interest based on current buffer state.
            //   client fd: src of c2p (read) + dst of p2c (write)
            //   peer fd:   src of p2c (read) + dst of c2p (write)
            let want_client = if_flag(c2p.want_read(), EV_IN) | if_flag(p2c.want_write(), EV_OUT);
            let want_peer = if_flag(p2c.want_read(), EV_IN) | if_flag(c2p.want_write(), EV_OUT);

            if want_client != client_interest {
                epoll_mod(epfd, client_fd, want_client, TAG_CLIENT)?;
                client_interest = want_client;
            }
            if want_peer != peer_interest {
                epoll_mod(epfd, peer_fd, want_peer, TAG_PEER)?;
                peer_interest = want_peer;
            }

            // Defensive: if neither fd has any interest but we are not done,
            // there is nothing to wait for — avoid blocking forever.
            if want_client == 0 && want_peer == 0 {
                break;
            }

            // SAFETY: `epfd` is the open epoll fd; `events` is a valid array of >= 2
            // epoll_event the kernel fills.
            let nfds = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 2, EPOLL_TIMEOUT_MS) };
            if nfds < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            // nfds == 0 → timeout; loop re-evaluates and waits again.

            let mut hangup = false;
            for ev in events.iter().take(nfds as usize) {
                let flags = ev.events;
                match ev.u64 {
                    TAG_CLIENT => {
                        if flags & EV_IN != 0 {
                            c2p.pump_read(&mut stats.splice_calls)?;
                        }
                        if flags & EV_OUT != 0 {
                            p2c.pump_write(&mut stats.splice_calls)?;
                        }
                        if flags & EV_HUP != 0 {
                            hangup = true;
                        }
                    }
                    TAG_PEER => {
                        if flags & EV_IN != 0 {
                            p2c.pump_read(&mut stats.splice_calls)?;
                        }
                        if flags & EV_OUT != 0 {
                            c2p.pump_write(&mut stats.splice_calls)?;
                        }
                        if flags & EV_HUP != 0 {
                            hangup = true;
                        }
                    }
                    _ => {}
                }
            }

            // Opportunistically flush anything just read, so a single epoll
            // cycle can both read and write when the destination is ready.
            // EAGAIN here is harmless (handled inside pump_write).
            c2p.pump_write(&mut stats.splice_calls)?;
            p2c.pump_write(&mut stats.splice_calls)?;

            // Propagate half-close once a direction is fully drained.
            c2p.maybe_propagate_eof();
            p2c.maybe_propagate_eof();

            if hangup {
                // One side dropped (RST/close). Best-effort flush already done
                // above; stop relaying. A closed socket cannot receive the
                // remaining buffered bytes, so there is nothing else to do.
                break;
            }
        }

        stats.client_to_peer_bytes = c2p.relayed;
        stats.peer_to_client_bytes = p2c.relayed;
        Ok(stats)
    })
    .await
    .map_err(io::Error::other)?
}

/// Closes the epoll fd when the loop returns (including on the `?` early
/// returns), so we never leak it on an error path.
struct EpollGuard(RawFd);

impl Drop for EpollGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the epoll fd owned by this guard, closed once in Drop.
        unsafe {
            libc::close(self.0);
        }
    }
}

#[inline]
fn if_flag(cond: bool, flag: u32) -> u32 {
    if cond {
        flag
    } else {
        0
    }
}

fn epoll_add(epfd: RawFd, fd: RawFd, events: u32, tag: u64) -> io::Result<()> {
    epoll_ctl(epfd, fd, events, tag, libc::EPOLL_CTL_ADD)
}

fn epoll_mod(epfd: RawFd, fd: RawFd, events: u32, tag: u64) -> io::Result<()> {
    epoll_ctl(epfd, fd, events, tag, libc::EPOLL_CTL_MOD)
}

fn epoll_ctl(epfd: RawFd, fd: RawFd, events: u32, tag: u64, op: libc::c_int) -> io::Result<()> {
    let mut ev = libc::epoll_event { events, u64: tag };
    // SAFETY: `epfd`/`fd` are open; `ev` is a valid initialized epoll_event living
    // for the call.
    let ret = unsafe { libc::epoll_ctl(epfd, op, fd, &mut ev) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Check if splice is available on this system.
pub fn is_splice_available() -> bool {
    // Try a harmless pipe2 call to check.
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a valid [c_int; 2] the kernel fills; flags are valid.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return false;
    }
    // SAFETY: fds[0]/fds[1] are the pipe ends just created, closed once each here.
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_creation() {
        let pipe = SplicePipe::new().unwrap();
        assert!(pipe.read_fd >= 0);
        assert!(pipe.write_fd >= 0);
        assert_ne!(pipe.read_fd, pipe.write_fd);
        // Capacity is the kernel-granted size (>= a page; usually == PIPE_SIZE).
        assert!(pipe.capacity > 0);
    }

    #[test]
    fn splice_available() {
        assert!(is_splice_available());
    }

    #[test]
    fn interest_tracks_buffer_state() {
        let pipe = SplicePipe::new().unwrap();
        let cap = pipe.capacity;
        let mut d = Direction::new(10, 11, pipe);

        // Fresh: want to read, nothing to write.
        assert!(d.want_read());
        assert!(!d.want_write());

        // Buffered data: want to write; still want to read while there is room.
        d.pending = 100;
        assert!(d.want_write());
        assert!(d.want_read());

        // Pipe full: stop reading (prevents EPOLLIN busy-loop), keep writing.
        d.pending = cap;
        assert!(!d.want_read());
        assert!(d.want_write());

        // Source closed and drained: fully done.
        d.pending = 0;
        d.src_eof = true;
        assert!(!d.want_read());
        assert!(!d.want_write());
        assert!(d.done());
    }
}
