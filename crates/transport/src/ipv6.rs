//! IPv6 Dual-Stack Transport
//!
//! - Dual-stack режим (IPV6_V6ONLY=0) для приёма IPv4 клиентов на IPv6 сокете
//! - Relay-сокеты в семействе клиента
//! - XOR-MAPPED-ADDRESS encode/decode для IPv6 (RFC 5389 §15.2)
//! - Нормализация IPv4-mapped IPv6 (::ffff:x.x.x.x → чистый IPv4)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use thiserror::Error;
use tracing::info;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum Ipv6Error {
    #[error("socket creation failed: {0}")]
    SocketCreation(#[source] std::io::Error),

    #[error("setsockopt {option}: {source}")]
    SetSockOpt {
        option: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("bind to {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("address family mismatch: client={client}, peer={peer}")]
    FamilyMismatch {
        client: &'static str,
        peer: &'static str,
    },
}

pub type Result<T> = std::result::Result<T, Ipv6Error>;

// ---------------------------------------------------------------------------
// Address Family
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    IPv4,
    IPv6,
}

impl AddressFamily {
    /// IPv4-mapped IPv6 (::ffff:x.x.x.x) считается IPv4.
    pub fn from_addr(addr: &SocketAddr) -> Self {
        match addr.ip() {
            IpAddr::V4(_) => Self::IPv4,
            IpAddr::V6(v6) => {
                if v6.to_ipv4_mapped().is_some() {
                    Self::IPv4
                } else {
                    Self::IPv6
                }
            }
        }
    }

    pub fn as_domain(&self) -> Domain {
        match self {
            Self::IPv4 => Domain::IPV4,
            Self::IPv6 => Domain::IPV6,
        }
    }

    /// STUN family byte: 0x01=IPv4, 0x02=IPv6 (RFC 5389 §15.1)
    pub fn stun_byte(&self) -> u8 {
        match self {
            Self::IPv4 => 0x01,
            Self::IPv6 => 0x02,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::IPv4 => "IPv4",
            Self::IPv6 => "IPv6",
        }
    }
}

// ---------------------------------------------------------------------------
// Dual-Stack Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DualStackConfig {
    pub enable_dual_stack: bool,
    pub listen_ipv4: Ipv4Addr,
    pub listen_ipv6: Ipv6Addr,
    pub external_ipv4: Option<Ipv4Addr>,
    pub external_ipv6: Option<Ipv6Addr>,
    pub reuse_addr: bool,
    pub reuse_port: bool,
    pub recv_buffer_size: Option<usize>,
    pub send_buffer_size: Option<usize>,
}

impl Default for DualStackConfig {
    fn default() -> Self {
        Self {
            enable_dual_stack: true,
            listen_ipv4: Ipv4Addr::UNSPECIFIED,
            listen_ipv6: Ipv6Addr::UNSPECIFIED,
            external_ipv4: None,
            external_ipv6: None,
            reuse_addr: true,
            reuse_port: false,
            recv_buffer_size: Some(2 * 1024 * 1024),
            send_buffer_size: Some(2 * 1024 * 1024),
        }
    }
}

// ---------------------------------------------------------------------------
// Socket Factory
// ---------------------------------------------------------------------------

pub struct SocketFactory {
    config: DualStackConfig,
}

impl SocketFactory {
    pub fn new(config: DualStackConfig) -> Self {
        Self { config }
    }

    /// Relay-сокет в том же семействе, что и клиент.
    pub fn create_relay_socket(
        &self,
        client_family: AddressFamily,
        relay_port: u16,
    ) -> Result<Socket> {
        let bind_addr = self.bind_addr(client_family, relay_port);
        let socket = self.create_udp(client_family)?;

        socket
            .bind(&SockAddr::from(bind_addr))
            .map_err(|e| Ipv6Error::Bind { addr: bind_addr, source: e })?;

        info!(family = client_family.label(), port = relay_port, "relay socket created");
        Ok(socket)
    }

    /// Dual-stack listener: один IPv6 сокет принимает оба семейства.
    pub fn create_dual_stack_listener(&self, port: u16) -> Result<Socket> {
        let socket = self.create_udp(AddressFamily::IPv6)?;

        socket.set_only_v6(false).map_err(|e| Ipv6Error::SetSockOpt {
            option: "IPV6_V6ONLY=0",
            source: e,
        })?;

        let addr = SocketAddr::V6(SocketAddrV6::new(self.config.listen_ipv6, port, 0, 0));
        socket
            .bind(&SockAddr::from(addr))
            .map_err(|e| Ipv6Error::Bind { addr, source: e })?;

        info!(port, %addr, "dual-stack listener (IPV6_V6ONLY=0)");
        Ok(socket)
    }

    fn create_udp(&self, family: AddressFamily) -> Result<Socket> {
        let socket = Socket::new(family.as_domain(), Type::DGRAM, Some(Protocol::UDP))
            .map_err(Ipv6Error::SocketCreation)?;

        if self.config.reuse_addr {
            socket.set_reuse_address(true).map_err(|e| Ipv6Error::SetSockOpt {
                option: "SO_REUSEADDR",
                source: e,
            })?;
        }

        #[cfg(target_os = "linux")]
        if self.config.reuse_port {
            socket.set_reuse_port(true).map_err(|e| Ipv6Error::SetSockOpt {
                option: "SO_REUSEPORT",
                source: e,
            })?;
        }

        if let Some(size) = self.config.recv_buffer_size {
            let _ = socket.set_recv_buffer_size(size);
        }
        if let Some(size) = self.config.send_buffer_size {
            let _ = socket.set_send_buffer_size(size);
        }

        socket.set_nonblocking(true).map_err(|e| Ipv6Error::SetSockOpt {
            option: "O_NONBLOCK",
            source: e,
        })?;

        if family == AddressFamily::IPv6 {
            socket.set_only_v6(true).map_err(|e| Ipv6Error::SetSockOpt {
                option: "IPV6_V6ONLY=1",
                source: e,
            })?;
        }

        Ok(socket)
    }

    fn bind_addr(&self, family: AddressFamily, port: u16) -> SocketAddr {
        match family {
            AddressFamily::IPv4 => SocketAddr::V4(SocketAddrV4::new(self.config.listen_ipv4, port)),
            AddressFamily::IPv6 => {
                SocketAddr::V6(SocketAddrV6::new(self.config.listen_ipv6, port, 0, 0))
            }
        }
    }

    /// Внешний адрес для XOR-MAPPED-ADDRESS.
    pub fn external_addr(&self, family: AddressFamily, port: u16) -> Option<SocketAddr> {
        match family {
            AddressFamily::IPv4 => self
                .config
                .external_ipv4
                .map(|ip| SocketAddr::V4(SocketAddrV4::new(ip, port))),
            AddressFamily::IPv6 => self
                .config
                .external_ipv6
                .map(|ip| SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))),
        }
    }
}

// ---------------------------------------------------------------------------
// XOR Address Encoding (IPv6-aware, RFC 5389 §15.2)
// ---------------------------------------------------------------------------

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

#[derive(Debug, Clone)]
pub struct XorMappedAddress {
    pub family: AddressFamily,
    pub port: u16,
    pub address: XorAddressBytes,
}

#[derive(Debug, Clone)]
pub enum XorAddressBytes {
    V4([u8; 4]),
    V6([u8; 16]),
}

pub fn xor_encode_address(addr: &SocketAddr, txn_id: &[u8; 12]) -> XorMappedAddress {
    let xor_port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

    match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip().octets();
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            XorMappedAddress {
                family: AddressFamily::IPv4,
                port: xor_port,
                address: XorAddressBytes::V4([
                    ip[0] ^ cookie[0],
                    ip[1] ^ cookie[1],
                    ip[2] ^ cookie[2],
                    ip[3] ^ cookie[3],
                ]),
            }
        }
        SocketAddr::V6(v6) => {
            let ip = v6.ip().octets();
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            mask[4..16].copy_from_slice(txn_id);

            let mut xor_ip = [0u8; 16];
            for i in 0..16 {
                xor_ip[i] = ip[i] ^ mask[i];
            }
            XorMappedAddress {
                family: AddressFamily::IPv6,
                port: xor_port,
                address: XorAddressBytes::V6(xor_ip),
            }
        }
    }
}

pub fn xor_decode_address(xor: &XorMappedAddress, txn_id: &[u8; 12]) -> SocketAddr {
    let port = xor.port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

    match &xor.address {
        XorAddressBytes::V4(xip) => {
            let c = STUN_MAGIC_COOKIE.to_be_bytes();
            let ip = Ipv4Addr::new(xip[0] ^ c[0], xip[1] ^ c[1], xip[2] ^ c[2], xip[3] ^ c[3]);
            SocketAddr::V4(SocketAddrV4::new(ip, port))
        }
        XorAddressBytes::V6(xip) => {
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            mask[4..16].copy_from_slice(txn_id);

            let mut ip = [0u8; 16];
            for i in 0..16 {
                ip[i] = xip[i] ^ mask[i];
            }
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0))
        }
    }
}

impl XorMappedAddress {
    /// Serialize for STUN attribute value.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20);
        buf.push(0x00); // reserved
        buf.push(self.family.stun_byte());
        buf.extend_from_slice(&self.port.to_be_bytes());
        match &self.address {
            XorAddressBytes::V4(ip) => buf.extend_from_slice(ip),
            XorAddressBytes::V6(ip) => buf.extend_from_slice(ip),
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let port = u16::from_be_bytes([data[2], data[3]]);
        match data[1] {
            0x01 if data.len() >= 8 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(&data[4..8]);
                Some(Self { family: AddressFamily::IPv4, port, address: XorAddressBytes::V4(a) })
            }
            0x02 if data.len() >= 20 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&data[4..20]);
                Some(Self { family: AddressFamily::IPv6, port, address: XorAddressBytes::V6(a) })
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Normalization & Compatibility
// ---------------------------------------------------------------------------

/// ::ffff:x.x.x.x → чистый IPv4 (для permission check).
pub fn normalize_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, v6.port())),
            None => addr,
        },
        other => other,
    }
}

pub fn check_family_compatibility(client: &SocketAddr, peer: &SocketAddr) -> Result<()> {
    let cf = AddressFamily::from_addr(client);
    let pf = AddressFamily::from_addr(peer);
    if cf != pf {
        return Err(Ipv6Error::FamilyMismatch {
            client: cf.label(),
            peer: pf.label(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_detection() {
        let v4: SocketAddr = "192.168.1.1:3478".parse().unwrap();
        assert_eq!(AddressFamily::from_addr(&v4), AddressFamily::IPv4);

        let v6: SocketAddr = "[2001:db8::1]:3478".parse().unwrap();
        assert_eq!(AddressFamily::from_addr(&v6), AddressFamily::IPv6);

        let mapped = SocketAddr::V6(SocketAddrV6::new(
            "::ffff:192.168.1.1".parse().unwrap(), 3478, 0, 0,
        ));
        assert_eq!(AddressFamily::from_addr(&mapped), AddressFamily::IPv4);
    }

    #[test]
    fn xor_roundtrip_v4() {
        let addr: SocketAddr = "192.0.2.1:32853".parse().unwrap();
        let txn = [0u8; 12];
        let enc = xor_encode_address(&addr, &txn);
        assert_eq!(xor_decode_address(&enc, &txn), addr);
    }

    #[test]
    fn xor_roundtrip_v6() {
        let addr: SocketAddr = "[2001:db8::1]:32853".parse().unwrap();
        let txn = [0xAB; 12];
        let enc = xor_encode_address(&addr, &txn);
        assert_eq!(enc.family, AddressFamily::IPv6);
        assert_eq!(xor_decode_address(&enc, &txn), addr);
    }

    #[test]
    fn xor_serialization_roundtrip() {
        let addr: SocketAddr = "[2001:db8::1]:9999".parse().unwrap();
        let txn = [0x42; 12];
        let enc = xor_encode_address(&addr, &txn);
        let bytes = enc.to_bytes();
        let parsed = XorMappedAddress::from_bytes(&bytes).unwrap();
        assert_eq!(xor_decode_address(&parsed, &txn), addr);
    }

    #[test]
    fn normalize_mapped() {
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            "::ffff:10.0.0.1".parse().unwrap(), 8080, 0, 0,
        ));
        assert_eq!(normalize_addr(mapped), "10.0.0.1:8080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn family_compat() {
        let v4a: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let v4b: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        assert!(check_family_compatibility(&v4a, &v4b).is_ok());

        let v6: SocketAddr = "[2001:db8::1]:5678".parse().unwrap();
        assert!(check_family_compatibility(&v4a, &v6).is_err());
    }
}
