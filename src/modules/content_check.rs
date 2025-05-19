use crate::types::PacketInfo;
use crate::modules::PacketModule;

pub struct ContentCheckModule;

impl ContentCheckModule {
    pub fn new() -> Self {
        ContentCheckModule
    }
}

impl PacketModule for ContentCheckModule {
    fn name(&self) -> &'static str {
        "ContentCheckModule"
    }

    #[allow(unused)]
    fn process(&self, packet_info: &mut PacketInfo) -> bool {
        true
    }
}
