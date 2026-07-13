//! STUN/TURN method definitions

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Method {
    // STUN
    Binding = 0x0001,
    // TURN
    Allocate = 0x0003,
    Refresh = 0x0004,
    Send = 0x0006,
    Data = 0x0007,
    CreatePermission = 0x0008,
    ChannelBind = 0x0009,
    // TURN TCP relay (RFC 6062)
    Connect = 0x000A,
    ConnectionBind = 0x000B,
    ConnectionAttempt = 0x000C,
}

impl Method {
    pub fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            0x0001 => Some(Self::Binding),
            0x0003 => Some(Self::Allocate),
            0x0004 => Some(Self::Refresh),
            0x0006 => Some(Self::Send),
            0x0007 => Some(Self::Data),
            0x0008 => Some(Self::CreatePermission),
            0x0009 => Some(Self::ChannelBind),
            0x000A => Some(Self::Connect),
            0x000B => Some(Self::ConnectionBind),
            0x000C => Some(Self::ConnectionAttempt),
            _ => None,
        }
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }
}
