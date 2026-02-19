use dashmap::DashMap;
use std::net::Ipv4Addr;
use ipnet::Ipv4Net;

pub struct FakeIpManager {
    range: Ipv4Net,
    // Map: Domain -> Fake IP
    #[allow(dead_code)]
    domain_to_ip: DashMap<String, Ipv4Addr>,
    ip_to_domain: DashMap<Ipv4Addr, String>,
    #[allow(dead_code)]
    next_index: std::sync::atomic::AtomicU32,
}

impl FakeIpManager {
    pub fn new(range_str: &str) -> Self {
        let range: Ipv4Net = range_str.parse().unwrap_or("198.18.0.0/16".parse().unwrap());
        Self {
            range,
            domain_to_ip: DashMap::new(),
            ip_to_domain: DashMap::new(),
            next_index: std::sync::atomic::AtomicU32::new(1),
        }
    }

    #[allow(dead_code)]
    pub fn get_or_assign_ip(&self, domain: &str) -> Ipv4Addr {
        if let Some(ip) = self.domain_to_ip.get(domain) {
            return *ip;
        }

        let base_ip_u32 = u32::from(self.range.network());
        let offset = self.next_index.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let fake_ip = Ipv4Addr::from(base_ip_u32 + offset);

        self.domain_to_ip.insert(domain.to_string(), fake_ip);
        self.ip_to_domain.insert(fake_ip, domain.to_string());
        
        fake_ip
    }

    pub fn get_domain(&self, ip: Ipv4Addr) -> Option<String> {
        self.ip_to_domain.get(&ip).map(|d| d.clone())
    }

    pub fn is_fake_ip(&self, ip: Ipv4Addr) -> bool {
        self.range.contains(&ip)
    }
}
