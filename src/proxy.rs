use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::sync::Arc;
use tracing::{info, debug, warn};
use crate::session::SessionManager;
use crate::fake_ip::FakeIpManager;

use crate::config::{AppConfig, ProxyProtocol};
use parking_lot::RwLock;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio_rustls::TlsConnector;

pub async fn run_tcp_proxy(
    local_port: u16, 
    app_config: Arc<RwLock<AppConfig>>, 
    session_manager: Arc<SessionManager>,
    fake_ip_manager: Arc<FakeIpManager>
) -> io::Result<()> {
    // Listen on all interfaces (0.0.0.0) to accept redirected packets from WinDivert
    // WinDivert redirects packets by swapping src/dst IP, so the dest IP becomes the original src IP
    let listener = TcpListener::bind(format!("0.0.0.0:{}", local_port)).await?;
    info!("TCP 本地代理服务器监听在: 0.0.0.0:{}", local_port);

    loop {
        let (mut client_stream, peer_addr) = listener.accept().await?;
        debug!("New local connection from {}", peer_addr);
        let session_manager = session_manager.clone();
        let fake_ip_manager = fake_ip_manager.clone();
        let config = app_config.clone();
        
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_connection(&mut client_stream, config, peer_addr, session_manager, fake_ip_manager).await {
                warn!("TCP connection handled ({}): {}", peer_addr, e);
            }
        });
    }
}

async fn handle_tcp_connection(
    client_stream: &mut TcpStream, 
    app_config: Arc<RwLock<AppConfig>>,
    client_addr: std::net::SocketAddr, 
    session_manager: Arc<SessionManager>,
    fake_ip_manager: Arc<FakeIpManager>
) -> io::Result<()> {
    // 1. 获取拦截时的原始目标
    let src_port = client_addr.port();
    let session = session_manager.get_session(src_port).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, format!("找不到端口 {} 对应的原始 Session", src_port))
    })?;

    // 2. 选择代理
    let proxy = {
        let config = app_config.read();
        let proxies = &config.proxies;
        if let Some(ref name) = session.proxy_name {
            proxies.iter().find(|p| &p.name == name).or(proxies.get(0)).cloned()
        } else {
            proxies.get(0).cloned()
        }
    }.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "未配置代理节点"))?;

    let target_host = if fake_ip_manager.is_fake_ip(session.orig_dest_ip) {
        fake_ip_manager.get_domain(session.orig_dest_ip).map(|d| d.to_string()).unwrap_or_else(|| session.orig_dest_ip.to_string())
    } else {
        session.orig_dest_ip.to_string()
    };
    let is_domain = fake_ip_manager.is_fake_ip(session.orig_dest_ip) && fake_ip_manager.get_domain(session.orig_dest_ip).is_some();

    info!("Connection Accepted: {} -> {} (via {} [{}])", client_addr, target_host, proxy.name, proxy.protocol.as_str());

    let proxy_addr = format!("{}:{}", proxy.host, proxy.port);
    let mut proxy_stream_raw = TcpStream::connect(&proxy_addr).await?;

    // 3. 处理不同协议的握手
    match proxy.protocol {
        ProxyProtocol::Socks5 => {
            handle_socks5_handshake(&mut proxy_stream_raw, &target_host, session.orig_dest_port, is_domain, session.orig_dest_ip).await?;
            forward_streams(client_stream, &mut proxy_stream_raw).await
        }
        ProxyProtocol::Http => {
            handle_http_connect_handshake(&mut proxy_stream_raw, &target_host, session.orig_dest_port).await?;
            forward_streams(client_stream, &mut proxy_stream_raw).await
        }
        ProxyProtocol::Https => {
            let connector = create_tls_connector()?;
            let server_name = ServerName::try_from(proxy.host.as_str())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("无效的代理主机名: {}", e)))?
                .to_owned();
            let mut tls_stream = connector.connect(server_name, proxy_stream_raw).await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS 连接代理失败: {}", e)))?;
            
            handle_http_connect_handshake(&mut tls_stream, &target_host, session.orig_dest_port).await?;
            forward_streams(client_stream, &mut tls_stream).await
        }
    }
}

async fn forward_streams<S1, S2>(s1: &mut S1, s2: &mut S2) -> io::Result<()>
where S1: AsyncReadExt + AsyncWriteExt + Unpin,
      S2: AsyncReadExt + AsyncWriteExt + Unpin
{
    let (mut r1, mut w1) = io::split(s1);
    let (mut r2, mut w2) = io::split(s2);

    let copy1 = io::copy(&mut r1, &mut w2);
    let copy2 = io::copy(&mut r2, &mut w1);

    tokio::try_join!(copy1, copy2)?;
    Ok(())
}

async fn handle_http_connect_handshake<S>(
    stream: &mut S,
    target_host: &str,
    target_port: u16,
) -> io::Result<()> 
where S: AsyncReadExt + AsyncWriteExt + Unpin 
{
    let request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
        target_host, target_port, target_host, target_port
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    let mut buffer = [0u8; 1];
    loop {
        stream.read_exact(&mut buffer).await?;
        response.push(buffer[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
        if response.len() > 4096 {
            return Err(io::Error::new(io::ErrorKind::Other, "HTTP 响应过长"));
        }
    }

    let resp_str = String::from_utf8_lossy(&response);
    if resp_str.contains(" 200 ") {
        Ok(())
    } else {
        let first_line = resp_str.lines().next().unwrap_or("");
        Err(io::Error::new(io::ErrorKind::Other, format!("HTTP 代理连接失败: {}", first_line)))
    }
}

async fn handle_socks5_handshake<S>(
    stream: &mut S,
    target_host: &str,
    target_port: u16,
    is_domain: bool,
    ipv4_addr: std::net::Ipv4Addr,
) -> io::Result<()>
where S: AsyncReadExt + AsyncWriteExt + Unpin
{
    // 1. SOCKS5 握手 (No Auth)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting_resp = [0u8; 2];
    stream.read_exact(&mut greeting_resp).await?;
    if greeting_resp[0] != 0x05 || greeting_resp[1] != 0x00 {
        return Err(io::Error::new(io::ErrorKind::Other, "SOCKS5 握手失败或需要认证"));
    }

    // 2. SOCKS5 CONNECT 请求
    let mut request = vec![0x05, 0x01, 0x00];
    if is_domain {
        request.push(0x03); // ATYP: Domain Name
        request.push(target_host.len() as u8);
        request.extend_from_slice(target_host.as_bytes());
    } else {
        request.push(0x01); // ATYP: IPv4
        request.extend_from_slice(&ipv4_addr.octets());
    }
    request.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&request).await?;

    // 3. 读取 CONNECT 响应
    let mut connect_resp = [0u8; 4];
    stream.read_exact(&mut connect_resp).await?;
    if connect_resp[1] != 0x00 {
        return Err(io::Error::new(io::ErrorKind::Other, format!("SOCKS5 连接目标失败, 错误码: {}", connect_resp[1])));
    }

    // 读取剩余部分 (根据 ATYP)
    match connect_resp[3] {
        0x01 => { // IPv4
            let mut addr = [0u8; 6];
            stream.read_exact(&mut addr).await?;
        }
        0x03 => { // Domain
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut domain).await?;
        }
        0x04 => { // IPv6
            let mut addr = [0u8; 18];
            stream.read_exact(&mut addr).await?;
        }
        _ => return Err(io::Error::new(io::ErrorKind::Other, "不支持的 SOCKS5 地址类型")),
    }

    Ok(())
}

fn create_tls_connector() -> io::Result<TlsConnector> {
    let mut root_cert_store = RootCertStore::empty();
    let result = rustls_native_certs::load_native_certs();
    for cert in result.certs {
        root_cert_store.add(cert).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}
