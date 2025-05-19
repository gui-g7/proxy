use crate::redis_manager::RedisManager;
use crate::types::{BlockTarget, IpAddress, Port};
use std::io::{self, Write};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub async fn command_loop(
    redis_manager: Arc<RedisManager>,
    show_packet_info: Arc<AtomicBool>,
    metrics_module: Arc<crate::modules::metrics::MetricsModule>,
) {
    println!("Proxy CLI started. Type 'help' for commands.");
    loop {
        print!("proxy> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("Error reading command.");
            continue;
        }

        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "help" => {
                println!("Available commands:");
                println!("  show on|off            - Toggle display of packet information");
                println!("  block ip <ip_address>  - Block an IP address");
                println!("  unblock ip <ip_address>- Unblock an IP address");
                println!("  block port <port_num>  - Block traffic to/from a port");
                println!("  unblock port <port_num>- Unblock traffic to/from a port");
                println!("  block ipport <ip> <port> - Block specific IP:Port combination");
                println!("  unblock ipport <ip> <port> - Unblock specific IP:Port combination");
                println!("  status                 - Show current status (blocked items, stats)");
                println!("  quit | exit            - Shutdown the proxy");
            }
            "show" => {
                if parts.len() > 1 {
                    match parts[1] {
                        "on" => {
                            show_packet_info.store(true, Ordering::SeqCst);
                            println!("Packet info display ON.");
                        }
                        "off" => {
                            show_packet_info.store(false, Ordering::SeqCst);
                            println!("Packet info display OFF.");
                        }
                        _ => println!("Usage: show on|off"),
                    }
                } else {
                    println!("Usage: show on|off");
                }
            }
            "block" => {
                if parts.len() < 3 {
                    println!("Usage: block <ip|port|ipport> <value> [<port_value_if_ipport>]");
                    continue;
                }
                match parts[1] {
                    "ip" => {
                        if let Ok(ip) = IpAddress::from_str(parts[2]) {
                            if let Err(e) = redis_manager.add_to_blocklist(BlockTarget::Ip(ip)) {
                                eprintln!("Error blocking IP {}: {}", ip, e);
                            } else {
                                println!("IP {} added to blocklist.", ip);
                            }
                        } else {
                            println!("Invalid IP address: {}", parts[2]);
                        }
                    }
                    "port" => {
                        if let Ok(port) = parts[2].parse::<Port>() {
                             if let Err(e) = redis_manager.add_to_blocklist(BlockTarget::Port(port)) {
                                eprintln!("Error blocking port {}: {}", port, e);
                            } else {
                                println!("Port {} added to blocklist.", port);
                            }
                        } else {
                            println!("Invalid port number: {}", parts[2]);
                        }
                    }
                     "ipport" => {
                        if parts.len() < 4 {
                            println!("Usage: block ipport <ip_address> <port_num>");
                            continue;
                        }
                        if let Ok(ip) = IpAddress::from_str(parts[2]) {
                            if let Ok(port) = parts[3].parse::<Port>() {
                                if let Err(e) = redis_manager.add_to_blocklist(BlockTarget::IpPort(ip, port)) {
                                    eprintln!("Error blocking IP:Port {}:{}: {}", ip, port, e);
                                } else {
                                    println!("IP:Port {}:{} added to blocklist.", ip, port);
                                }
                            } else {
                                println!("Invalid port number: {}", parts[3]);
                            }
                        } else {
                            println!("Invalid IP address: {}", parts[2]);
                        }
                    }
                    _ => println!("Usage: block <ip|port|ipport> <value> ..."),
                }
            }
            "unblock" => {
                 if parts.len() < 3 {
                    println!("Usage: unblock <ip|port|ipport> <value> [<port_value_if_ipport>]");
                    continue;
                }
                match parts[1] {
                    "ip" => {
                        if let Ok(ip) = IpAddress::from_str(parts[2]) {
                            if let Err(e) = redis_manager.remove_from_blocklist(BlockTarget::Ip(ip)) {
                                eprintln!("Error unblocking IP {}: {}", ip, e);
                            } else {
                                println!("IP {} removed from blocklist.", ip);
                            }
                        } else {
                            println!("Invalid IP address: {}", parts[2]);
                        }
                    }
                    "port" => {
                        if let Ok(port) = parts[2].parse::<Port>() {
                             if let Err(e) = redis_manager.remove_from_blocklist(BlockTarget::Port(port)) {
                                eprintln!("Error unblocking port {}: {}", port, e);
                            } else {
                                println!("Port {} removed from blocklist.", port);
                            }
                        } else {
                            println!("Invalid port number: {}", parts[2]);
                        }
                    }
                    "ipport" => {
                        if parts.len() < 4 {
                            println!("Usage: unblock ipport <ip_address> <port_num>");
                            continue;
                        }
                        if let Ok(ip) = IpAddress::from_str(parts[2]) {
                            if let Ok(port) = parts[3].parse::<Port>() {
                                if let Err(e) = redis_manager.remove_from_blocklist(BlockTarget::IpPort(ip, port)) {
                                    eprintln!("Error unblocking IP:Port {}:{}: {}", ip, port, e);
                                } else {
                                    println!("IP:Port {}:{} removed from blocklist.", ip, port);
                                }
                            } else {
                                println!("Invalid port number: {}", parts[3]);
                            }
                        } else {
                            println!("Invalid IP address: {}", parts[2]);
                        }
                    }
                    _ => println!("Usage: unblock <ip|port|ipport> <value> ..."),
                }
            }
            "status" => {
                println!("--- Proxy Status ---");
                println!("Packet Info Display: {}", if show_packet_info.load(Ordering::SeqCst) { "ON" } else { "OFF" });
                
                match redis_manager.get_blocked_ips() {
                    Ok(ips) => println!("Blocked IPs: {:?}", ips),
                    Err(e) => eprintln!("Error fetching blocked IPs: {}", e),
                }
                match redis_manager.get_blocked_ports() {
                    Ok(ports) => println!("Blocked Ports: {:?}", ports),
                    Err(e) => eprintln!("Error fetching blocked ports: {}", e),
                }
                let (packets, bytes) = metrics_module.get_stats();
                println!("Packets Processed: {}", packets);
                println!("Bytes Processed: {}", bytes);
                println!("--------------------");
            }
            "quit" | "exit" => {
                println!("Shutting down proxy...");
                std::process::exit(0);
            }
            _ => {
                println!("Unknown command: {}. Type 'help' for available commands.", parts[0]);
            }
        }
    }
}
