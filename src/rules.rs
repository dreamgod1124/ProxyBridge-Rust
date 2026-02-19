use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use ipnet::Ipv4Net;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Proxy(String),   // Matches: { proxy = "name" }
    #[serde(rename = "default")]
    DefaultProxy,    // Matches: "default"
    Direct,
    Block,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Both,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ips: Option<Vec<String>>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ports: Option<Vec<u16>>,
    pub protocol: Protocol,
    pub action: RuleAction,
    
    // Internal cache for regex matching
    #[serde(skip)]
    pub proc_regex: Option<regex::Regex>,
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    pub default_action: RuleAction,
}

impl RuleEngine {
    pub fn new(mut rules: Vec<Rule>, default_action: RuleAction) -> Self {
        // Pre-compile regex for process name patterns
        for rule in &mut rules {
            if let Some(ref pat) = rule.process_name {
                let p_pat = pat.to_lowercase();
                if p_pat.contains('*') || p_pat.contains('?') {
                    let mut regex_pat = String::from("^");
                    for c in p_pat.chars() {
                        match c {
                            '*' => regex_pat.push_str(".*"),
                            '?' => regex_pat.push('.'),
                            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                                regex_pat.push('\\');
                                regex_pat.push(c);
                            }
                            _ => regex_pat.push(c),
                        }
                    }
                    regex_pat.push('$');
                    rule.proc_regex = regex::Regex::new(&regex_pat).ok();
                }
            }
        }
        Self { rules, default_action }
    }

    pub fn match_rule(&self, process: &str, dest_ip: Ipv4Addr, dest_port: u16, is_udp: bool) -> RuleAction {
        // If there are NO rules defined, the default should be PROXY
        // so that users don't see "empty monitor" on first start.
        if self.rules.is_empty() {
            return RuleAction::DefaultProxy;
        }

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            match (&rule.protocol, is_udp) {
                (Protocol::Tcp, true) => continue,
                (Protocol::Udp, false) => continue,
                _ => {}
            }

            if let Some(ref proc_pattern) = rule.process_name {
                let p_proc = process.to_lowercase();
                
                let matches = if let Some(ref re) = rule.proc_regex {
                    re.is_match(&p_proc)
                } else {
                    // Fallback to simple contains (no wildcards)
                    p_proc.contains(&proc_pattern.to_lowercase())
                };

                if !matches {
                    continue;
                }
            }

            if let Some(ref ips) = rule.target_ips {
                let mut ip_matched = false;
                for ip_str in ips {
                    if let Ok(net) = ip_str.parse::<Ipv4Net>() {
                        if net.contains(&dest_ip) {
                            ip_matched = true;
                            break;
                        }
                    } else if let Ok(addr) = ip_str.parse::<Ipv4Addr>() {
                        if addr == dest_ip {
                            ip_matched = true;
                            break;
                        }
                    } else if ip_str == "*" {
                        ip_matched = true;
                        break;
                    }
                }
                if !ip_matched {
                    continue;
                }
            }

            if let Some(ref ports) = rule.target_ports {
                if !ports.contains(&dest_port) {
                    continue;
                }
            }

            return rule.action.clone();
        }

        // Return the configured default action if no rule matches
        self.default_action.clone()
    }
}
