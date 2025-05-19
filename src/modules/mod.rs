use crate::types::PacketInfo;

pub mod metrics;
pub mod content_check;

pub trait PacketModule: Send + Sync {
    fn name(&self) -> &'static str;
    fn process(&self, packet_info: &mut PacketInfo) -> bool;
}
