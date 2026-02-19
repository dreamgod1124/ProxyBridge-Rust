use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use anyhow::{Result, Context};
use crate::rules::{Rule, RuleAction};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    #[default]
    Socks5,
    Http,
    Https,
}

impl ProxyProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "http" => Self::Http,
            "https" => Self::Https,
            _ => Self::Socks5,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProxyConfig {
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub protocol: ProxyProtocol,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppConfig {
    pub proxies: Vec<ProxyConfig>,
    pub local_proxy_port: u16,
    pub local_udp_relay_port: u16,
    pub fake_ip_enabled: bool,
    pub fake_ip_range: String,
    pub logging_enabled: bool,
    pub monitor_enabled: bool,
    pub rules: Vec<Rule>,
    pub default_action: RuleAction,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            proxies: vec![ProxyConfig {
                name: "Default".into(),
                host: "127.0.0.1".into(),
                port: 1080,
                protocol: ProxyProtocol::Socks5,
            }],
            local_proxy_port: 34010,
            local_udp_relay_port: 34011,
            fake_ip_enabled: false,
            fake_ip_range: "198.18.0.0/16".into(),
            logging_enabled: true,
            monitor_enabled: true,
            rules: vec![],
            default_action: RuleAction::Direct,
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let path = Path::new("config.toml");
        if path.exists() {
            let content = fs::read_to_string(path).context("读取配置文件失败")?;
            toml::from_str(&content).context("解析配置文件失败")
        } else {
            let config = Self::default();
            config.save()?;
            Ok(config)
        }
    }

    pub fn save(&self) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("序列化配置失败: {}", e))?;
        fs::write("config.toml", content).context("写入配置文件失败")
    }
}
