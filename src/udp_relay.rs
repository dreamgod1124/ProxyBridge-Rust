use tokio::net::UdpSocket;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use crate::session::SessionManager;
use crate::fake_ip::FakeIpManager;
use tracing::{info, debug, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use dashmap::DashMap;
use std::time::Instant;

use crate::config::AppConfig;
use parking_lot::RwLock;

struct UdpAssociation {
    relay_socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    #[allow(dead_code)]
    last_active: RwLock<Instant>,
    // The TCP stream must be kept alive to maintain the SOCKS5 UDP association
    _control_task: tokio::task::JoinHandle<()>,
}

type AssociationPool = Arc<DashMap<u16, Arc<UdpAssociation>>>;

pub async fn run_udp_relay(
    local_port: u16, 
    app_config: Arc<RwLock<AppConfig>>, 
    session_manager: Arc<SessionManager>,
    fake_ip_manager: Arc<FakeIpManager>
) -> tokio::io::Result<()> {
    let socket = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await?);
    info!("UDP 转发服务器监听在: 0.0.0.0:{}", local_port);

    let pool: AssociationPool = Arc::new(DashMap::new());
    
    // Cleanup task for idle associations
    let pool_cleanup = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let now = Instant::now();
            pool_cleanup.retain(|_, assoc| {
                let last = assoc.last_active.read();
                if now.duration_since(*last).as_secs() > 60 {
                    debug!("Cleaning up idle UDP association");
                    false
                } else {
                    true
                }
            });
        }
    });

    let mut buf = [0u8; 65535];
    loop {
        let (len, peer_addr) = socket.recv_from(&mut buf).await?;
        let data = buf[..len].to_vec();
        
        let sm = session_manager.clone();
        let fm = fake_ip_manager.clone();
        let socket_c = socket.clone();
        let config = app_config.clone();
        let pool_c = pool.clone();
        
        tokio::spawn(async move {
            if let Err(e) = handle_udp_packet_optimized(data, peer_addr, config, sm, fm, socket_c, pool_c).await {
                warn!("UDP packet handled ({}): {}", peer_addr, e);
            }
        });
    }
}

async fn handle_udp_packet_optimized(
    data: Vec<u8>, 
    peer_addr: SocketAddr, 
    app_config: Arc<RwLock<AppConfig>>,
    session_manager: Arc<SessionManager>,
    fake_ip_manager: Arc<FakeIpManager>,
    main_socket: Arc<UdpSocket>,
    pool: AssociationPool
) -> tokio::io::Result<()> {
    let src_port = peer_addr.port();
    
    // 1. Get or create association
    let assoc = if let Some(a) = pool.get(&src_port) {
        *a.last_active.write() = Instant::now();
        a.clone()
    } else {
        let a = create_udp_association(peer_addr, app_config.clone(), session_manager.clone(), fake_ip_manager.clone(), main_socket.clone()).await?;
        let a_arc = Arc::new(a);
        pool.insert(src_port, a_arc.clone());
        a_arc
    };

    // 2. Build SOCKS5 UDP header
    let session = session_manager.get_session(src_port).ok_or_else(|| {
        tokio::io::Error::new(tokio::io::ErrorKind::NotFound, "UDP session lost")
    })?;

    let mut packet = vec![0x00, 0x00, 0x00];
    if fake_ip_manager.is_fake_ip(session.orig_dest_ip) {
        if let Some(domain) = fake_ip_manager.get_domain(session.orig_dest_ip) {
            packet.push(0x03); 
            packet.push(domain.len() as u8);
            packet.extend_from_slice(domain.as_bytes());
        } else {
            packet.push(0x01);
            packet.extend_from_slice(&session.orig_dest_ip.octets());
        }
    } else {
        packet.push(0x01);
        packet.extend_from_slice(&session.orig_dest_ip.octets());
    }
    packet.extend_from_slice(&session.orig_dest_port.to_be_bytes());
    packet.extend_from_slice(&data);

    // 3. Send to relay
    assoc.relay_socket.send_to(&packet, assoc.relay_addr).await?;
    
    Ok(())
}

async fn create_udp_association(
    peer_addr: SocketAddr,
    app_config: Arc<RwLock<AppConfig>>,
    session_manager: Arc<SessionManager>,
    _fake_ip_manager: Arc<FakeIpManager>,
    main_socket: Arc<UdpSocket>
) -> tokio::io::Result<UdpAssociation> {
    let src_port = peer_addr.port();
    let session = session_manager.get_session(src_port).ok_or_else(|| {
        tokio::io::Error::new(tokio::io::ErrorKind::NotFound, "UDP session Mapping not found")
    })?;

    let proxy = {
        let config = app_config.read();
        let proxies = &config.proxies;
        if let Some(ref name) = session.proxy_name {
            proxies.iter().find(|p| &p.name == name).or(proxies.get(0)).cloned()
        } else {
            proxies.get(0).cloned()
        }
    }.ok_or_else(|| tokio::io::Error::new(tokio::io::ErrorKind::Other, "No proxy configured"))?;

    let socks5_addr = format!("{}:{}", proxy.host, proxy.port);
    debug!("Creating new UDP association for {} via {}", peer_addr, proxy.name);

    let mut control_stream = TcpStream::connect(&socks5_addr).await?;
    control_stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    control_stream.read_exact(&mut resp).await?;
    if resp[1] != 0x00 {
        return Err(tokio::io::Error::new(tokio::io::ErrorKind::Other, "SOCKS5 Auth failed"));
    }

    // UDP ASSOCIATE
    control_stream.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    let mut assoc_resp = [0u8; 10];
    control_stream.read_exact(&mut assoc_resp).await?;

    if assoc_resp[1] != 0x00 {
        return Err(tokio::io::Error::new(tokio::io::ErrorKind::Other, "UDP Associate failed"));
    }

    let relay_ip = Ipv4Addr::new(assoc_resp[4], assoc_resp[5], assoc_resp[6], assoc_resp[7]);
    let relay_p = u16::from_be_bytes([assoc_resp[8], assoc_resp[9]]);
    let relay_addr = SocketAddr::V4(SocketAddrV4::new(relay_ip, relay_p));

    let relay_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    
    // Spawn a task to keep TCP alive and listen for UDP responses
    let relay_socket_c = relay_socket.clone();
    let main_socket_c = main_socket.clone();
    let control_task = tokio::spawn(async move {
        let mut recv_buf = [0u8; 65535];
        let mut tcp_buf = [0u8; 1];
        
        loop {
            tokio::select! {
                // Keep TCP alive or detect closure
                res = control_stream.read(&mut tcp_buf) => {
                    match res {
                        Ok(0) | Err(_) => {
                            debug!("UDP SOCKS5 control connection closed for {}", peer_addr);
                            break;
                        }
                        _ => {}
                    }
                }
                // Forward UDP responses back to client
                res = relay_socket_c.recv_from(&mut recv_buf) => {
                    match res {
                        Ok((len, _)) => {
                            let resp_data = &recv_buf[..len];
                            if resp_data.len() > 10 {
                                let atyp = resp_data[3];
                                let data_start = match atyp {
                                    0x01 => 10,
                                    0x03 => 7 + resp_data[4] as usize,
                                    0x04 => 22,
                                    _ => continue,
                                };
                                if resp_data.len() > data_start {
                                    let payload = &resp_data[data_start..];
                                    let _ = main_socket_c.send_to(payload, peer_addr).await;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Timeout after inactivity could be handled here if needed, 
                // but the pool cleanup handles it.
            }
        }
    });

    Ok(UdpAssociation {
        relay_socket,
        relay_addr,
        last_active: RwLock::new(Instant::now()),
        _control_task: control_task,
    })
}
