use crate::types::{PacketInfo, BlockTarget};
use redis::{Client, Commands, RedisResult, Connection};
use std::sync::{Arc, Mutex};

#[allow(unused)]
use std::time::Duration;

const REDIS_PACKET_KEY_PREFIX: &str = "proxy:packet:";
const REDIS_PACKET_TTL_SECONDS: usize = 3600;
const REDIS_BLOCKLIST_IPS_KEY: &str = "proxy:blocklist:ips";
const REDIS_BLOCKLIST_PORTS_KEY: &str = "proxy:blocklist:ports";

pub struct RedisManager {
    conn: Arc<Mutex<Connection>>,
}

impl RedisManager {
    pub fn new(redis_url: &str) -> RedisResult<Self> {
        let client = Client::open(redis_url)?;
        let conn = client.get_connection()?;
        Ok(RedisManager {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn get_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap()
    }

    pub fn store_packet_info(&self, packet_info: &PacketInfo) -> RedisResult<()> {
        let key = format!("{}{}", REDIS_PACKET_KEY_PREFIX, packet_info.uid);
        let packet_json = serde_json::to_string(packet_info)
            .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "Serialization error", e.to_string())))?;
        let _: () = self.get_conn().set_ex(key, packet_json, REDIS_PACKET_TTL_SECONDS as u64)?;
        Ok(())
    }

    pub fn add_to_blocklist(&self, target: BlockTarget) -> RedisResult<()> {
        let mut conn = self.get_conn();
        match target {
            BlockTarget::Ip(ip) => {
                let _added_count: i64 = conn.sadd(REDIS_BLOCKLIST_IPS_KEY, ip.to_string())?;
            }
            BlockTarget::Port(port) => {
                let _added_count: i64 = conn.sadd(REDIS_BLOCKLIST_PORTS_KEY, port)?;
            }
            BlockTarget::IpPort(ip, port) => {
                let key = format!("proxy:blocklist:ipport:{}:{}", ip, port);
                let _: () = conn.set_ex(key, true, (REDIS_PACKET_TTL_SECONDS * 24 * 7) as u64)?;
            }
        }
        Ok(())
    }

    pub fn remove_from_blocklist(&self, target: BlockTarget) -> RedisResult<()> {
        let mut conn = self.get_conn();
        match target {
            BlockTarget::Ip(ip) => {
                let _removed_count: i64 = conn.srem(REDIS_BLOCKLIST_IPS_KEY, ip.to_string())?;
            }
            BlockTarget::Port(port) => {
                let _removed_count: i64 = conn.srem(REDIS_BLOCKLIST_PORTS_KEY, port)?;
            }
             BlockTarget::IpPort(ip, port) => {
                let key = format!("proxy:blocklist:ipport:{}:{}", ip, port);
                let _deleted_count: i64 = conn.del(key)?;
            }
        }
        Ok(())
    }

    pub fn is_blocked(&self, ip: Option<&crate::types::IpAddress>, port: Option<crate::types::Port>) -> RedisResult<bool> {
        let mut conn = self.get_conn();
        if let Some(ip_addr) = ip {
            if conn.sismember(REDIS_BLOCKLIST_IPS_KEY, ip_addr.to_string())? {
                return Ok(true);
            }
        }
        if let Some(p) = port {
            if conn.sismember(REDIS_BLOCKLIST_PORTS_KEY, p)? {
                return Ok(true);
            }
        }
        if let (Some(ip_addr), Some(p)) = (ip, port) {
            let key = format!("proxy:blocklist:ipport:{}:{}", ip_addr, p);
            if conn.exists(key)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn get_blocked_ips(&self) -> RedisResult<Vec<String>> {
        self.get_conn().smembers(REDIS_BLOCKLIST_IPS_KEY)
    }

    pub fn get_blocked_ports(&self) -> RedisResult<Vec<u16>> {
        self.get_conn().smembers(REDIS_BLOCKLIST_PORTS_KEY)
    }
}
