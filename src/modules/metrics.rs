use crate::types::PacketInfo;
use crate::modules::PacketModule;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct MetricsModule {
    packets_processed: AtomicU64,
    bytes_processed: AtomicU64,
}

impl MetricsModule {
    pub fn new() -> Self {
        MetricsModule {
            packets_processed: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
        }
    }

    pub fn get_stats(&self) -> (u64, u64) {
        (
            self.packets_processed.load(Ordering::Relaxed),
            self.bytes_processed.load(Ordering::Relaxed),
        )
    }
}

impl PacketModule for MetricsModule {
    fn name(&self) -> &'static str {
        "MetricsModule"
    }

    fn process(&self, packet_info: &mut PacketInfo) -> bool {
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
        self.bytes_processed.fetch_add(packet_info.packet_length, Ordering::Relaxed);
        println!("[Metrics] Packet {} processed. Total: {}, Bytes: {}", packet_info.uid, self.packets_processed.load(Ordering::Relaxed), self.bytes_processed.load(Ordering::Relaxed));
        true
    }
}
