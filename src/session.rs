use dashmap::DashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct SessionInfo {
    #[allow(dead_code)]
    pub src_ip: Ipv4Addr,
    #[allow(dead_code)]
    pub src_port: u16,
    pub orig_dest_ip: Ipv4Addr,
    pub orig_dest_port: u16,
    pub last_activity: Instant,
    pub start_time: Instant,
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    pub proxy_name: Option<String>,
    pub process_name: String,
    pub display_dest: String,
    pub action_display: String,
}

pub struct SessionManager {
    // Key: source port (used as unique identifier for outbound connections)
    // Value: session information
    sessions: DashMap<u16, SessionInfo>,
    
    // Stats or other global state can be added here
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    pub fn add_session(&self, src_port: u16, info: SessionInfo) {
        self.sessions.insert(src_port, info);
    }

    pub fn get_session(&self, src_port: u16) -> Option<SessionInfo> {
        self.sessions.get(&src_port).map(|s| s.clone())
    }

    pub fn get_all_sessions(&self) -> Vec<SessionInfo> {
        self.sessions.iter().map(|entry| entry.value().clone()).collect()
    }

    #[allow(dead_code)]
    pub fn remove_session(&self, src_port: u16) {
        self.sessions.remove(&src_port);
    }

    #[allow(dead_code)]
    pub fn cleanup_stale(&self, timeout_secs: u64) {
        let now = Instant::now();
        self.sessions.retain(|_, info| {
            now.duration_since(info.last_activity).as_secs() < timeout_secs
        });
    }

    #[allow(dead_code)]
    pub fn update_activity(&self, _src_port: u16) {
        // Implementation...
    }

    pub fn update_traffic(&self, src_port: u16, sent: u64, recv: u64) {
        if let Some(mut info) = self.sessions.get_mut(&src_port) {
            info.sent_bytes += sent;
            info.recv_bytes += recv;
            info.last_activity = Instant::now();
        }
    }
}
