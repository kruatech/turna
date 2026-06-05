//! Graceful Restart — zero-downtime через FD passing + shared memory
//!
//! 1. New process → Unix socket → Old process
//! 2. Old → FDs через SCM_RIGHTS + state через memfd
//! 3. New восстанавливает аллокации → Old exits

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, info, warn};

const STATE_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum GracefulError {
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("serialize: {0}")]
    Serde(#[from] bincode::Error),
    #[error("shared memory: {0}")]
    Shm(String),
    #[error("fd passing: {0}")]
    FdPass(String),
    #[error("handshake: {0}")]
    Handshake(String),
    #[error("version mismatch: expected {expected}, got {got}")]
    Version { expected: u32, got: u32 },
}

pub type Result<T> = std::result::Result<T, GracefulError>;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct GracefulConfig {
    pub socket_path: PathBuf,
    pub handshake_timeout: Duration,
    pub transfer_timeout: Duration,
    pub max_shm_size: usize,
}

impl Default for GracefulConfig {
    fn default() -> Self {
        Self { socket_path: "/run/turna/graceful.sock".into(), handshake_timeout: Duration::from_secs(10), transfer_timeout: Duration::from_secs(30), max_shm_size: 64 * 1024 * 1024 }
    }
}

// ---------------------------------------------------------------------------
// Serializable State
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerState {
    pub version: u32,
    pub allocations: Vec<AllocState>,
    pub nonces: HashMap<String, NonceState>,
    pub port_map: HashMap<u16, String>,
    pub config_hash: u64,
    pub created_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AllocState {
    pub id: String,
    pub username: String,
    pub realm: String,
    pub client_addr: SocketAddr,
    pub relay_addr: SocketAddr,
    pub relay_port: u16,
    pub created_at: u64,
    pub expires_at: u64,
    pub transport: String,
    pub integrity_key: Vec<u8>,
    pub permissions: HashMap<SocketAddr, u64>,
    pub channels: HashMap<u16, (SocketAddr, u64)>,
    pub relay_fd_index: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NonceState {
    pub nonce: String,
    pub client_ip: String,
    pub created_at: u64,
}

// ---------------------------------------------------------------------------
// Handshake Protocol
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub enum HandshakeMsg {
    Ready { version: u32, pid: u32 },
    Accept { alloc_count: usize, fd_count: usize },
    StateTransferred,
    Restored { recovered: usize },
    OldCanExit,
    Error { msg: String },
}

fn write_msg(stream: &UnixStream, msg: &HandshakeMsg) -> Result<()> {
    let data = bincode::serialize(msg)?;
    let len = (data.len() as u32).to_be_bytes();
    let s = stream;
    (&*s).write_all(&len)?;
    (&*s).write_all(&data)?;
    (&*s).flush()?;
    Ok(())
}

fn read_msg(stream: &UnixStream) -> Result<HandshakeMsg> {
    let mut len_buf = [0u8; 4];
    let s = stream;
    (&*s).read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut data = vec![0u8; len];
    (&*s).read_exact(&mut data)?;
    Ok(bincode::deserialize(&data)?)
}

// ---------------------------------------------------------------------------
// FD Passing (SCM_RIGHTS)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn send_fds(sock: &UnixStream, fds: &[RawFd], data: &[u8]) -> Result<()> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, SockaddrStorage};
    let iov = [nix::sys::uio::IoSlice::new(data)];
    let cmsg = [ControlMessage::ScmRights(fds)];
    sendmsg::<SockaddrStorage>(sock.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
        .map_err(|e| GracefulError::FdPass(format!("sendmsg: {e}")))?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn recv_fds(sock: &UnixStream, max: usize) -> Result<(Vec<u8>, Vec<RawFd>)> {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    let mut buf = vec![0u8; 65536];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 256]);
    let mut iov = [nix::sys::uio::IoSliceMut::new(&mut buf)];
    let msg = recvmsg::<()>(sock.as_raw_fd(), &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
        .map_err(|e| GracefulError::FdPass(format!("recvmsg: {e}")))?;
    let data = buf[..msg.bytes].to_vec();
    let mut fds = Vec::new();
    for cmsg in msg.cmsgs() {
        if let ControlMessageOwned::ScmRights(f) = cmsg { fds.extend(f.iter().take(max)); }
    }
    Ok((data, fds))
}

// ---------------------------------------------------------------------------
// memfd State Transfer
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn create_state_memfd(state: &ServerState) -> Result<RawFd> {
    let data = bincode::serialize(state)?;
    let name = std::ffi::CString::new("turna-state").unwrap();
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 { return Err(GracefulError::Shm(format!("memfd_create: {}", io::Error::last_os_error()))); }
    // NEEDS-REVIEW: File::from_raw_fd transfers ownership of `fd`
    // into the File wrapper; mem::forget(f) below releases the wrapper
    // without closing. The fd is intentionally returned to caller. If
    // the caller ever loses the fd without close, it leaks. Idiom is
    // correct but easy to misuse; consider a typed FdHandle that
    // requires explicit close().
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    f.write_all(&data).map_err(|e| GracefulError::Shm(format!("write: {e}")))?;
    let raw = f.as_raw_fd();
    std::mem::forget(f);
    info!(bytes = data.len(), allocs = state.allocations.len(), "state → memfd");
    Ok(raw)
}

#[cfg(target_os = "linux")]
pub fn read_state_memfd(fd: RawFd) -> Result<ServerState> {
    use std::io::Seek;
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    f.seek(io::SeekFrom::Start(0)).map_err(|e| GracefulError::Shm(format!("seek: {e}")))?;
    let mut data = Vec::new();
    f.read_to_end(&mut data).map_err(|e| GracefulError::Shm(format!("read: {e}")))?;
    std::mem::forget(f);
    let state: ServerState = bincode::deserialize(&data)?;
    if state.version != STATE_VERSION { return Err(GracefulError::Version { expected: STATE_VERSION, got: state.version }); }
    info!(allocs = state.allocations.len(), "memfd → state");
    Ok(state)
}

// ---------------------------------------------------------------------------
// Sender (old process)
// ---------------------------------------------------------------------------

pub struct GracefulSender { config: GracefulConfig }

impl GracefulSender {
    pub fn new(config: GracefulConfig) -> Self { Self { config } }

    #[cfg(target_os = "linux")]
    pub fn execute(&self, state: ServerState, socket_fds: Vec<RawFd>) -> Result<()> {
        let _ = std::fs::remove_file(&self.config.socket_path);
        let listener = std::os::unix::net::UnixListener::bind(&self.config.socket_path)?;
        info!(path = %self.config.socket_path.display(), "waiting for new process...");
        let (stream, _) = listener.accept()?;

        match read_msg(&stream)? {
            HandshakeMsg::Ready { version, pid } => {
                if version != STATE_VERSION { write_msg(&stream, &HandshakeMsg::Error { msg: "version mismatch".into() })?; return Err(GracefulError::Version { expected: STATE_VERSION, got: version }); }
                info!(pid, "new process connected");
            }
            _ => return Err(GracefulError::Handshake("expected Ready".into())),
        }

        write_msg(&stream, &HandshakeMsg::Accept { alloc_count: state.allocations.len(), fd_count: socket_fds.len() })?;

        let state_fd = create_state_memfd(&state)?;
        let mut all_fds = vec![state_fd];
        all_fds.extend(&socket_fds);
        send_fds(&stream.try_clone()?, &all_fds, b"fds")?;
        write_msg(&stream, &HandshakeMsg::StateTransferred)?;

        match read_msg(&stream)? {
            HandshakeMsg::Restored { recovered } => info!(recovered, total = state.allocations.len(), "new process restored"),
            HandshakeMsg::Error { msg } => { error!(%msg, "new process error"); return Err(GracefulError::Handshake(msg)); }
            _ => return Err(GracefulError::Handshake("expected Restored".into())),
        }

        match read_msg(&stream)? { HandshakeMsg::OldCanExit => info!("permission to exit"), _ => warn!("unexpected msg, exiting anyway") }
        let _ = std::fs::remove_file(&self.config.socket_path);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Receiver (new process)
// ---------------------------------------------------------------------------

pub struct RestoredState { pub state: ServerState, pub socket_fds: Vec<RawFd> }

pub struct GracefulReceiver { config: GracefulConfig }

impl GracefulReceiver {
    pub fn new(config: GracefulConfig) -> Self { Self { config } }

    #[cfg(target_os = "linux")]
    pub fn try_restore(&self) -> Result<Option<RestoredState>> {
        if !self.config.socket_path.exists() { info!("no socket, fresh start"); return Ok(None); }
        let stream = UnixStream::connect(&self.config.socket_path)?;
        write_msg(&stream, &HandshakeMsg::Ready { version: STATE_VERSION, pid: std::process::id() })?;

        let (alloc_count, fd_count) = match read_msg(&stream)? {
            HandshakeMsg::Accept { alloc_count, fd_count } => (alloc_count, fd_count),
            HandshakeMsg::Error { msg } => return Err(GracefulError::Handshake(msg)),
            _ => return Err(GracefulError::Handshake("expected Accept".into())),
        };
        info!(alloc_count, fd_count, "receiving state...");

        let (_, fds) = recv_fds(&stream.try_clone()?, fd_count + 1)?;
        if fds.is_empty() { return Err(GracefulError::FdPass("no fds".into())); }

        match read_msg(&stream)? { HandshakeMsg::StateTransferred => {} _ => return Err(GracefulError::Handshake("expected StateTransferred".into())) }

        let state = read_state_memfd(fds[0])?;
        let socket_fds = fds[1..].to_vec();

        write_msg(&stream, &HandshakeMsg::Restored { recovered: state.allocations.len() })?;
        write_msg(&stream, &HandshakeMsg::OldCanExit)?;
        info!(allocs = state.allocations.len(), fds = socket_fds.len(), "graceful restore complete");
        Ok(Some(RestoredState { state, socket_fds }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_serde() {
        let s = ServerState { version: STATE_VERSION, allocations: vec![], nonces: HashMap::new(), port_map: HashMap::new(), config_hash: 123, created_at: 1700000000 };
        let data = bincode::serialize(&s).unwrap();
        let r: ServerState = bincode::deserialize(&data).unwrap();
        assert_eq!(r.version, STATE_VERSION);
        assert_eq!(r.config_hash, 123);
    }

    #[test]
    fn msg_serde() {
        let m = HandshakeMsg::Ready { version: 1, pid: 999 };
        let data = bincode::serialize(&m).unwrap();
        match bincode::deserialize::<HandshakeMsg>(&data).unwrap() {
            HandshakeMsg::Ready { version: 1, pid: 999 } => {}
            _ => panic!("wrong msg"),
        }
    }
}
