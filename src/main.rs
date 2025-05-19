mod types;
mod packet_handler;
mod redis_manager;
mod cli;
mod modules;

#[allow(unused)]
use pnet::datalink::{self, NetworkInterface, Channel};
#[allow(unused)]
use pnet::packet::Packet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
#[allow(unused)]
use types::PacketInfo;
use modules::{PacketModule, metrics::MetricsModule, content_check::ContentCheckModule};

const REDIS_URL: &str = "redis://127.0.0.1/";

#[tokio::main]
async fn main() {
    println!("Rust Proxy starting...");

    // --- Configuração Inicial ---
    let show_packet_info = Arc::new(AtomicBool::new(true));
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\nCtrl+C received, shutting down...");
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");
    let redis_manager = match redis_manager::RedisManager::new(REDIS_URL) {
        Ok(manager) => Arc::new(manager),
        Err(e) => {
            eprintln!("Failed to connect to Redis: {}", e);
            std::process::exit(1);
        }
    };
    println!("Connected to Redis at {}", REDIS_URL);
    let metrics_module = Arc::new(MetricsModule::new());
    let content_check_module = Arc::new(ContentCheckModule::new());
    let processing_modules: Vec<Arc<dyn PacketModule>> = vec![
        metrics_module.clone() as Arc<dyn PacketModule>,
        content_check_module.clone() as Arc<dyn PacketModule>,
    ];


    // --- Thread da CLI ---
    let cli_redis_manager = redis_manager.clone();
    let cli_show_packet_info = show_packet_info.clone();
    let cli_metrics_module = metrics_module.clone();
    let cli_running_flag = running.clone();

    tokio::spawn(async move {
        cli::command_loop(cli_redis_manager, cli_show_packet_info, cli_metrics_module).await;
        cli_running_flag.store(false, Ordering::SeqCst);
    });
    // --- Captura de Pacotes ---
    let interfaces = datalink::interfaces();
    let default_interface = interfaces.iter().find(|iface| {
        iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty()
    });

    let interface = match default_interface {
        Some(iface) => iface.clone(),
        None => {
            eprintln!("No suitable network interface found. Please select one manually or check your network configuration.");
            if interfaces.is_empty() {
                 eprintln!("No network interfaces detected at all.");
            } else {
                eprintln!("Available interfaces:");
                for iface in interfaces {
                    println!("  - Name: {}, Up: {}, Loopback: {}, IPs: {:?}", iface.name, iface.is_up(), iface.is_loopback(), iface.ips);
                }
                eprintln!("Consider using one of the interfaces listed above if suitable.");
            }
            std::process::exit(1);
        }
    };
    
    println!("Monitoring network interface: {}", interface.name);
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("Unhandled channel type for interface {}", interface.name);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error creating datalink channel for interface {}: {}", interface.name, e);
            eprintln!("Hint: You might need to run this program with superuser privileges (e.g., sudo).");
            std::process::exit(1);
        }
    };

    println!("Packet capturing started. Press Ctrl+C or type 'quit' in CLI to stop.");
    // --- Loop Principal de Processamento de Pacotes ---
    while running.load(Ordering::SeqCst) {
        match rx.next() {
            Ok(packet_data) => {
                if let Some(mut packet_info) = packet_handler::parse_packet(&interface.name, packet_data) {
                    let src_ip_blocked = redis_manager.is_blocked(Some(&packet_info.source_ip), None).unwrap_or(false);
                    let dst_ip_blocked = redis_manager.is_blocked(Some(&packet_info.destination_ip), None).unwrap_or(false);
                    let src_port_blocked = if let Some(sp) = packet_info.source_port {
                        redis_manager.is_blocked(None, Some(sp)).unwrap_or(false) || 
                        redis_manager.is_blocked(Some(&packet_info.source_ip), Some(sp)).unwrap_or(false)
                    } else { false };
                    let dst_port_blocked = if let Some(dp) = packet_info.destination_port {
                        redis_manager.is_blocked(None, Some(dp)).unwrap_or(false) ||
                        redis_manager.is_blocked(Some(&packet_info.destination_ip), Some(dp)).unwrap_or(false)
                    } else { false };

                    if src_ip_blocked || dst_ip_blocked || src_port_blocked || dst_port_blocked {
                        packet_info.is_blocked = true;
                    }
                    let mut continue_processing = true;
                    for module in &processing_modules {
                        if !module.process(&mut packet_info) {
                            println!("[Proxy Core] Module '{}' stopped processing for packet {}", module.name(), packet_info.uid);
                            continue_processing = false;
                            break; 
                        }
                    }

                    if !continue_processing {
                         if let Err(e) = redis_manager.store_packet_info(&packet_info) {
                            eprintln!("[Redis] Error storing blocked packet {}: {}", packet_info.uid, e);
                        }
                        if show_packet_info.load(Ordering::SeqCst) {
                             println!("[Blocked by Module] {:?}", packet_info);
                        }
                        continue;
                    }
                    if packet_info.is_blocked {
                        if show_packet_info.load(Ordering::SeqCst) {
                            println!("[Blocked by Rule] {:?}", packet_info);
                        }
                    } else {
                        if show_packet_info.load(Ordering::SeqCst) {
                            println!("[Processed] {:?}", packet_info);
                        }
                    }
                    if let Err(e) = redis_manager.store_packet_info(&packet_info) {
                        eprintln!("[Redis] Error storing packet {}: {}", packet_info.uid, e);
                    }

                } else {
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::TimedOut {
                     eprintln!("[Pnet] Error receiving packet: {}", e);
                }
                 thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    println!("Proxy stopped.");
}
