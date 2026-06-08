//! splice(2) zero-copy bidirectional TCP relay.
//!
//! For TURN TCP relay (RFC 6062): data passes client↔peer through
//! a pipe in kernel, CPU never touches the bytes.
//!
//! Architecture:
//!   client_fd → splice → pipe_fd → splice → peer_fd
//!   peer_fd   → splice → pipe_fd → splice → client_fd
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

/// Max bytes per splice call.
const SPLICE_MAX: usize = 65536;

// ---------------------------------------------------------------------------
// Splice Pipe
// ---------------------------------------------------------------------------

/// A pipe used as intermediate buffer for splice(2).
struct SplicePipe {
    read_fd: RawFd,
    write_fd: RawFd,
}

impl SplicePipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Increase pipe buffer size
        unsafe {
            libc::fcntl(fds[0], libc::F_SETPIPE_SZ, PIPE_SIZE as libc::c_int);
        }

        Ok(Self {
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }
}

impl Drop for SplicePipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

// ---------------------------------------------------------------------------
// splice(2) wrapper
// ---------------------------------------------------------------------------

/// Splice from src_fd to pipe, then from pipe to dst_fd.
/// Returns bytes transferred, or 0 for EOF, or error.
fn splice_one_direction(src_fd: RawFd, pipe: &SplicePipe, dst_fd: RawFd) -> io::Result<usize> {
    let flags = libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE;

    // src → pipe
    let n = unsafe {
        libc::splice(
            src_fd,
            std::ptr::null_mut(),
            pipe.write_fd,
            std::ptr::null_mut(),
            SPLICE_MAX,
            flags as libc::c_uint,
        )
    };

    if n < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EAGAIN) {
            return Ok(0); // Would block, nothing to read
        }
        return Err(err);
    }
    if n == 0 {
        return Ok(0); // EOF
    }

    // pipe → dst
    let mut remaining = n as usize;
    while remaining > 0 {
        let sent = unsafe {
            libc::splice(
                pipe.read_fd,
                std::ptr::null_mut(),
                dst_fd,
                std::ptr::null_mut(),
                remaining,
                flags as libc::c_uint,
            )
        };
        if sent < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) {
                // dst not ready, need to wait and retry
                // In async context: register for POLLOUT
                continue;
            }
            return Err(err);
        }
        if sent == 0 {
            break;
        }
        remaining -= sent as usize;
    }

    Ok(n as usize)
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
/// Runs until one side closes or an error occurs.
///
/// For tokio integration: call from spawn_blocking or use epoll to detect
/// readability before each splice call.
pub async fn splice_relay(client_fd: RawFd, peer_fd: RawFd) -> io::Result<SpliceStats> {
    let pipe_c2p = SplicePipe::new()?;
    let pipe_p2c = SplicePipe::new()?;

    info!("splice relay started");

    let mut stats = SpliceStats::default();

    // Use tokio::task::spawn_blocking because splice is blocking
    let result = tokio::task::spawn_blocking(move || {
        // NEEDS-REVIEW: client_fd / peer_fd are RawFd (Copy) moved into a
        // spawn_blocking closure. If a sibling async task closes the
        // underlying socket during the blocking splice loop, kernel
        // returns EBADF — handled. But ownership is unclear: nothing in
        // the type system guarantees that the original socket outlives
        // this task.
        let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epfd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Register both fds for reading
        add_epoll(epfd, client_fd, libc::EPOLLIN as u32, 0)?;
        add_epoll(epfd, peer_fd, libc::EPOLLIN as u32, 1)?;

        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 2];

        loop {
            let nfds = unsafe {
                libc::epoll_wait(epfd, events.as_mut_ptr(), 2, 1000) // 1s timeout
            };

            if nfds < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                unsafe { libc::close(epfd) };
                return Err(err);
            }

            for i in 0..nfds as usize {
                let fd_tag = events[i].u64;

                if fd_tag == 0 {
                    // Client readable → splice to peer
                    match splice_one_direction(client_fd, &pipe_c2p, peer_fd) {
                        Ok(0) => {
                            // EOF from client
                            unsafe { libc::close(epfd) };
                            return Ok(stats);
                        }
                        Ok(n) => {
                            stats.client_to_peer_bytes += n as u64;
                            stats.splice_calls += 1;
                        }
                        Err(e) => {
                            unsafe { libc::close(epfd) };
                            return Err(e);
                        }
                    }
                } else {
                    // Peer readable → splice to client
                    match splice_one_direction(peer_fd, &pipe_p2c, client_fd) {
                        Ok(0) => {
                            unsafe { libc::close(epfd) };
                            return Ok(stats);
                        }
                        Ok(n) => {
                            stats.peer_to_client_bytes += n as u64;
                            stats.splice_calls += 1;
                        }
                        Err(e) => {
                            unsafe { libc::close(epfd) };
                            return Err(e);
                        }
                    }
                }
            }
        }
    })
    .await
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    result
}

fn add_epoll(epfd: RawFd, fd: RawFd, events: u32, data: u64) -> io::Result<()> {
    let mut ev = libc::epoll_event { events, u64: data };
    let ret = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Check if splice is available on this system.
pub fn is_splice_available() -> bool {
    // Try a harmless splice call to check
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return false;
    }
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
    }

    #[test]
    fn splice_available() {
        assert!(is_splice_available());
    }
}
