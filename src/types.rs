use serde::{Serialize, Deserialize};
use std::net::IpAddr;
use chrono::{DateTime, Utc};

#[derive (Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    TCP,
    UDP,
    ICMP,
    ICMPv6,
    Unknown(u8),
}

impl From<u8> for ProtocolType {
    fn from(num: u8) -> Self {
        match num {
            1 => ProtocolType::ICMP,
            6 => ProtocolType::TCP,
            17 => ProtocolType::UDP,
            58 => ProtocolType::ICMPv6,
            _ => ProtocolType::Unknown(num),
        }
    }
}

impl ProtocolType {
    #[allow(unused)]
    pub fn to_u8(&self) -> u8 {
        match self {
            ProtocolType::ICMP => 1,
            ProtocolType::TCP => 6,
            ProtocolType::UDP => 17,
            ProtocolType::ICMPv6 => 58,
            ProtocolType::Unknown(n) => *n,
        }
    }
}

pub type IpAddress = IpAddr;
pub type Port = u16;
pub type PacketSize = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub uid: String,
    pub timestamp: DateTime<Utc>,
    pub interface_name: String,
    pub protocol: ProtocolType,
    pub source_ip: IpAddress,
    pub destination_ip: IpAddress,
    pub source_port: Option<Port>,
    pub destination_port: Option<Port>,
    pub packet_length: PacketSize,
    pub payload_length: PacketSize,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub payload_preview: Vec<u8>,
    pub is_blocked: bool,
}

#[derive (Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BlockTarget {
    Ip(IpAddress),
    Port(Port),
    IpPort(IpAddress, Port),
}
