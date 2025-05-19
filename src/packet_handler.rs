use crate::types::{PacketInfo, ProtocolType, Port, PacketSize, IpAddress};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::Packet;
use chrono::Utc;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

const PAYLOAD_PREVIEW_LENGTH: usize = 64;

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

pub fn parse_packet(interface_name: &str, raw_packet: &[u8]) -> Option<PacketInfo> {
    let ethernet_packet = EthernetPacket::new(raw_packet)?;

    let (
        protocol,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        payload_length,
        payload_data_vec,
    ): (ProtocolType, IpAddress, IpAddress, Option<Port>, Option<Port>, PacketSize, Vec<u8>) =
        match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
            let (sp, dp, pl, pd_vec, proto_num) = match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;
                    (
                        Some(tcp_packet.get_source()),
                        Some(tcp_packet.get_destination()),
                        tcp_packet.payload().len() as PacketSize,
                        tcp_packet.payload().to_vec(),
                        IpNextHeaderProtocols::Tcp.0,
                    )
                }
                IpNextHeaderProtocols::Udp => {
                    let udp_packet = UdpPacket::new(ipv4_packet.payload())?;
                    (
                        Some(udp_packet.get_source()),
                        Some(udp_packet.get_destination()),
                        udp_packet.payload().len() as PacketSize,
                        udp_packet.payload().to_vec(),
                        IpNextHeaderProtocols::Udp.0,
                    )
                }
                IpNextHeaderProtocols::Icmp => {
                    let icmp_packet = IcmpPacket::new(ipv4_packet.payload())?;
                    (
                        None,
                        None,
                        icmp_packet.payload().len() as PacketSize,
                        icmp_packet.payload().to_vec(),
                        IpNextHeaderProtocols::Icmp.0,
                    )
                }
                other_proto => (
                    None,
                    None,
                    ipv4_packet.payload().len() as PacketSize,
                    ipv4_packet.payload().to_vec(),
                    other_proto.0
                ),
            };
            (
                ProtocolType::from(proto_num),
                IpAddress::V4(ipv4_packet.get_source()),
                IpAddress::V4(ipv4_packet.get_destination()),
                sp,
                dp,
                pl,
                pd_vec,
            )
        }
        EtherTypes::Ipv6 => {
            let ipv6_packet = Ipv6Packet::new(ethernet_packet.payload())?;
            let (sp, dp, pl, pd_vec, proto_num) = match ipv6_packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_packet = TcpPacket::new(ipv6_packet.payload())?;
                    (
                        Some(tcp_packet.get_source()),
                        Some(tcp_packet.get_destination()),
                        tcp_packet.payload().len() as PacketSize,
                        tcp_packet.payload().to_vec(),
                        IpNextHeaderProtocols::Tcp.0,
                    )
                }
                IpNextHeaderProtocols::Udp => {
                    let udp_packet = UdpPacket::new(ipv6_packet.payload())?;
                    (
                        Some(udp_packet.get_source()),
                        Some(udp_packet.get_destination()),
                        udp_packet.payload().len() as PacketSize,
                        udp_packet.payload().to_vec(),
                        IpNextHeaderProtocols::Udp.0,
                    )
                }
                 IpNextHeaderProtocols::Icmpv6 => {
                    let icmpv6_packet = Icmpv6Packet::new(ipv6_packet.payload())?;
                    (
                        None,
                        None,
                        icmpv6_packet.payload().len() as PacketSize,
                        icmpv6_packet.payload().to_vec(),
                        IpNextHeaderProtocols::Icmpv6.0,
                    )
                }
                other_proto => (
                    None,
                    None,
                    ipv6_packet.payload().len() as PacketSize,
                    ipv6_packet.payload().to_vec(),
                    other_proto.0
                ),
            };
            (
                ProtocolType::from(proto_num),
                IpAddress::V6(ipv6_packet.get_source()),
                IpAddress::V6(ipv6_packet.get_destination()),
                sp,
                dp,
                pl,
                pd_vec,
            )
        }
        _ => return None,
    };
    
    let timestamp = Utc::now();
    let uid_base = (
        timestamp.timestamp_nanos_opt().unwrap_or_default(),
        &source_ip,
        &destination_ip,
        &source_port,
        &destination_port,
        &protocol,
        &payload_data_vec 
    );
    let uid = format!("{:x}", calculate_hash(&uid_base));

    Some(PacketInfo {
        uid,
        timestamp,
        interface_name: interface_name.to_string(),
        protocol,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        packet_length: raw_packet.len() as PacketSize,
        payload_length,
        payload_preview: payload_data_vec.iter().take(PAYLOAD_PREVIEW_LENGTH).cloned().collect(),
        is_blocked: false,
    })
}
