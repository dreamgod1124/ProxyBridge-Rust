mod proxy;
mod udp_relay;
mod rules;
mod session;
mod process;
mod config;
mod fake_ip;

use anyhow::Result;
use etherparse::{NetHeaders, PacketHeaders, TransportHeader, UdpHeader};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::task;

#[derive(Clone)]
struct TrafficUpdateEvent {
    process_name: String,
    dest_display: String,
    start_time: std::time::Instant,
    action_display: String,
}
use tracing::{error, info, debug, warn};
use windivert::prelude::*;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::borrow::Cow;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing_subscriber::prelude::*;

use crate::proxy::run_tcp_proxy;
use crate::udp_relay::run_udp_relay;
use crate::rules::{RuleAction, RuleEngine, Protocol, Rule};
use crate::session::{SessionInfo, SessionManager};
use crate::process::{get_pid_from_tcp_connection, get_pid_from_udp_connection, get_process_name};
use crate::config::{AppConfig, ProxyConfig, ProxyProtocol};
use crate::fake_ip::FakeIpManager;

use tray_icon::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState};
use muda::{Menu, MenuItem, MenuEvent};
use image::GenericImageView;
use windows::core::PCSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{FindWindowA, ShowWindow, SetForegroundWindow, SW_HIDE, SW_SHOW, SW_RESTORE};
use std::ffi::CString;

slint::include_modules!();

static LOGGING_ENABLED: AtomicBool = AtomicBool::new(true);

struct LocalTimer;

impl tracing_subscriber::fmt::time::FormatTime for LocalTimer {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        write!(w, "{}", chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.6f"))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_timer(LocalTimer)
        .with_target(false)
        .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
            if LOGGING_ENABLED.load(Ordering::SeqCst) {
                true
            } else {
                // If disabled, ONLY allow ERROR (silence WARN, INFO, DEBUG)
                metadata.level() <= &tracing::Level::ERROR
            }
        }))
        .with_filter(tracing_subscriber::EnvFilter::from_default_env()
            .add_directive(tracing::Level::DEBUG.into()));

    tracing_subscriber::registry()
        .with(fmt_layer)
        .init();

    let app_config = Arc::new(RwLock::new(AppConfig::load().unwrap_or_default()));
    
    // Set initial logging state
    {
        let cfg = app_config.read();
        LOGGING_ENABLED.store(cfg.logging_enabled, Ordering::SeqCst);
    }
    
    let ui = AppWindow::new()?;
    let ui_handle = ui.as_weak();

    // Initialize UI properties from config
    {
        let cfg = app_config.read();
        ui.set_default_rule_action(match cfg.default_action {
            RuleAction::Proxy(_) => "Proxy".into(),
            RuleAction::DefaultProxy => "Proxy".into(),
            RuleAction::Direct => "Direct".into(),
            RuleAction::Block => "Block".into(),
        });
        ui.set_fake_ip_enabled(cfg.fake_ip_enabled);
        ui.set_logging_enabled(cfg.logging_enabled);
        ui.set_monitor_enabled(cfg.monitor_enabled);
        
        let ui_rules: Vec<RuleData> = cfg.rules.iter().map(rule_to_ui).collect();
        ui.set_rules_list(ModelRc::from(std::rc::Rc::new(VecModel::from(ui_rules))));

        let ui_proxies: Vec<ProxyData> = cfg.proxies.iter().map(proxy_to_ui).collect();
        ui.set_proxies_list(ModelRc::from(std::rc::Rc::new(VecModel::from(ui_proxies))));
        
        let names: Vec<slint::SharedString> = cfg.proxies.iter().map(|p| p.name.clone().into()).collect();
        ui.set_proxy_names(ModelRc::from(std::rc::Rc::new(VecModel::from(names))));
    }

    // --- System Tray Setup ---
    let tray_menu = Menu::new();
    let tray_show = MenuItem::new("Show ProxyBridge", true, None);
    let tray_exit = MenuItem::new("Exit", true, None);
    let _ = tray_menu.append_items(&[&tray_show, &tray_exit]);

    let icon = {
        let img = image::open("icon.ico").expect("Could not load icon.ico");
        let (width, height) = img.dimensions();
        let rgba = img.to_rgba8().into_raw();
        tray_icon::Icon::from_rgba(rgba, width, height).expect("Failed to create tray icon")
    };

    let _tray_icon = Box::leak(Box::new(TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("ProxyBridge")
        .with_icon(icon.clone())
        .build()
        .unwrap()));

    // Handle Window Close -> Hide using Win32 API to keep event loop running
    ui.window().on_close_requested({
        move || {
            // Find window by title matches .slint file: "ProxyBridge High Performance Rust"
            if let Some(hwnd) = find_main_window_handle() {
                info!("Closing window: Hiding to tray via Win32 API");
                unsafe { let _ = ShowWindow(hwnd, SW_HIDE); }
            } else {
                error!("Failed to find main window handle for hiding!");
            }
            slint::CloseRequestResponse::KeepWindowShown
        }
    });

    // Handle Tray Menu Events in background
    let show_id = tray_show.id().clone();
    let exit_id = tray_exit.id().clone();
    
    // We'll use a standard thread to pump tray events since Slint's loop might be hidden
    // We move the icon into the thread to ensure it lives as long as the event pump
    std::thread::spawn({
        let ui_show = ui_handle.clone();
        move || {
            let menu_channel = MenuEvent::receiver();
            let tray_channel = TrayIconEvent::receiver();
            
            info!("Tray event pump started");
            
            loop {
                // Use blocking recv with timeout to keep things responsive without pegging CPU
                if let Ok(event) = menu_channel.recv_timeout(std::time::Duration::from_millis(100)) {
                    if event.id == show_id {
                        let _ = slint::invoke_from_event_loop({
                            let ui_show = ui_show.clone();
                            move || {
                                if let Some(ui) = ui_show.upgrade() {
                                    if let Some(hwnd) = find_main_window_handle() {
                                        unsafe { 
                                            let _ = ShowWindow(hwnd, SW_SHOW); 
                                            let _ = ShowWindow(hwnd, SW_RESTORE);
                                            let _ = SetForegroundWindow(hwnd);
                                        }
                                    }
                                    ui.window().show().unwrap();
                                }
                            }
                        });
                    } else if event.id == exit_id {
                        info!("Exiting via Tray Menu");
                        std::process::exit(0);
                    }
                }

                if let Ok(event) = tray_channel.recv_timeout(std::time::Duration::from_millis(10)) {
                    match event {
                        TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } => {
                            info!("Tray Left Click Detected");
                            let _ = slint::invoke_from_event_loop({
                                let ui_show = ui_show.clone();
                                move || {
                                    if let Some(ui) = ui_show.upgrade() {
                                        if let Some(hwnd) = find_main_window_handle() {
                                            unsafe { 
                                                let _ = ShowWindow(hwnd, SW_SHOW); 
                                                let _ = ShowWindow(hwnd, SW_RESTORE);
                                                let _ = SetForegroundWindow(hwnd);
                                            }
                                        }
                                        ui.window().show().unwrap();
                                        ui.window().request_redraw();
                                    }
                                }
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
    });

    let session_manager = Arc::new(SessionManager::new());
    let engine_running = Arc::new(std::sync::atomic::AtomicBool::new(false));
    
    let rule_engine = {
        let config = app_config.read();
        Arc::new(RwLock::new(RuleEngine::new(config.rules.clone(), config.default_action.clone())))
    };

    let fake_ip_manager = {
        let cfg = app_config.read();
        Arc::new(FakeIpManager::new(&cfg.fake_ip_range))
    };

    ui.on_toggle_proxy({
        let ui_handle = ui_handle.clone();
        let engine_running = engine_running.clone();
        move || {
            let ui = ui_handle.unwrap();
            let is_now_running = !ui.get_is_running();
            ui.set_is_running(is_now_running);
            engine_running.store(is_now_running, std::sync::atomic::Ordering::SeqCst);
            ui.set_status_text(if is_now_running { "Engine Active".into() } else { "Engine Stopped".into() });
            info!("User toggled proxy: Engine status = {}", is_now_running);
        }
    });

    ui.on_save_config({
        let app_config = app_config.clone();
        move |fake_enabled, log_enabled, mon_enabled| {
            let mut cfg = app_config.write();
            cfg.fake_ip_enabled = fake_enabled;
            cfg.logging_enabled = log_enabled;
            cfg.monitor_enabled = mon_enabled;
            
            // If enabling, set flag BEFORE logging so we see the log
            if log_enabled {
                LOGGING_ENABLED.store(true, Ordering::SeqCst);
            }

            if let Err(e) = cfg.save() {
                error!("Save config failed: {}", e);
            } else {
                info!("Config saved (FakeIP={}, Log={}, Mon={})", fake_enabled, log_enabled, mon_enabled);
            }
            
            // If disabling, set flag AFTER logging so we see the log
            if !log_enabled {
                LOGGING_ENABLED.store(false, Ordering::SeqCst);
            }
        }
    });

    ui.on_add_proxy({
        let app_config = app_config.clone();
        let ui_handle = ui_handle.clone();
        move |p_data| {
            let mut cfg = app_config.write();
            cfg.proxies.push(ProxyConfig {
                name: p_data.name.to_string(),
                host: p_data.host.to_string(),
                port: p_data.port.parse().unwrap_or(1080),
                protocol: ProxyProtocol::from_str(&p_data.protocol),
            });
            let _ = cfg.save();
            
            if let Some(ui) = ui_handle.upgrade() {
                let ui_proxies: Vec<ProxyData> = cfg.proxies.iter().map(proxy_to_ui).collect();
                ui.set_proxies_list(ModelRc::from(std::rc::Rc::new(VecModel::from(ui_proxies))));
                let names: Vec<slint::SharedString> = cfg.proxies.iter().map(|p| p.name.clone().into()).collect();
                ui.set_proxy_names(ModelRc::from(std::rc::Rc::new(VecModel::from(names))));
            }
        }
    });

    ui.on_update_proxy({
        let app_config = app_config.clone();
        let ui_handle = ui_handle.clone();
        let re = rule_engine.clone();
        move |idx, p_data| {
            let mut cfg = app_config.write();
            if (idx as usize) < cfg.proxies.len() {
                let old_name = cfg.proxies[idx as usize].name.clone();
                let new_name = p_data.name.to_string();

                cfg.proxies[idx as usize] = ProxyConfig {
                    name: new_name.clone(),
                    host: p_data.host.to_string(),
                    port: p_data.port.parse().unwrap_or(1080),
                    protocol: ProxyProtocol::from_str(&p_data.protocol),
                };

                // Sync rules using this proxy
                if old_name != new_name {
                    for rule in &mut cfg.rules {
                        if let RuleAction::Proxy(ref name) = rule.action {
                            if name == &old_name {
                                rule.action = RuleAction::Proxy(new_name.clone());
                            }
                        }
                    }
                    if let RuleAction::Proxy(ref name) = cfg.default_action {
                        if name == &old_name {
                            cfg.default_action = RuleAction::Proxy(new_name.clone());
                        }
                    }
                }

                let _ = cfg.save();
                
                // Update live engine
                *re.write() = RuleEngine::new(cfg.rules.clone(), cfg.default_action.clone());

                if let Some(ui) = ui_handle.upgrade() {
                    let ui_proxies: Vec<ProxyData> = cfg.proxies.iter().map(proxy_to_ui).collect();
                    ui.set_proxies_list(ModelRc::from(std::rc::Rc::new(VecModel::from(ui_proxies))));
                    let names: Vec<slint::SharedString> = cfg.proxies.iter().map(|p| p.name.clone().into()).collect();
                    ui.set_proxy_names(ModelRc::from(std::rc::Rc::new(VecModel::from(names))));
                    
                    // Also refresh rules in UI if names changed
                    if old_name != new_name {
                        let ui_rules: Vec<RuleData> = cfg.rules.iter().map(rule_to_ui).collect();
                        ui.set_rules_list(ModelRc::from(std::rc::Rc::new(VecModel::from(ui_rules))));
                    }
                }
            }
        }
    });

    ui.on_remove_proxy({
        let app_config = app_config.clone();
        let ui_handle = ui_handle.clone();
        let re = rule_engine.clone();
        move |idx| {
            let mut cfg = app_config.write();
            if (idx as usize) < cfg.proxies.len() {
                let name_to_remove = cfg.proxies[idx as usize].name.clone();
                cfg.proxies.remove(idx as usize);
                
                // Fix rules referencing removed proxy
                let mut rules_changed = false;
                for rule in &mut cfg.rules {
                    if let RuleAction::Proxy(ref name) = rule.action {
                        if name == &name_to_remove {
                            rule.action = RuleAction::DefaultProxy;
                            rules_changed = true;
                        }
                    }
                }
                if let RuleAction::Proxy(ref name) = cfg.default_action {
                    if name == &name_to_remove {
                        cfg.default_action = RuleAction::DefaultProxy;
                        rules_changed = true;
                    }
                }

                let _ = cfg.save();
                
                // Update live engine
                *re.write() = RuleEngine::new(cfg.rules.clone(), cfg.default_action.clone());

                if let Some(ui) = ui_handle.upgrade() {
                    let ui_proxies: Vec<ProxyData> = cfg.proxies.iter().map(proxy_to_ui).collect();
                    ui.set_proxies_list(ModelRc::from(std::rc::Rc::new(VecModel::from(ui_proxies))));
                    let names: Vec<slint::SharedString> = cfg.proxies.iter().map(|p| p.name.clone().into()).collect();
                    ui.set_proxy_names(ModelRc::from(std::rc::Rc::new(VecModel::from(names))));
                    
                    if rules_changed {
                        let ui_rules: Vec<RuleData> = cfg.rules.iter().map(rule_to_ui).collect();
                        ui.set_rules_list(ModelRc::from(std::rc::Rc::new(VecModel::from(ui_rules))));
                    }
                }
            }
        }
    });

    ui.on_update_rule({
        let app_config = app_config.clone();
        let re = rule_engine.clone();
        let ui_handle = ui_handle.clone();
        move |idx, rule_data| {
            let rule = ui_to_rule(rule_data);
            let mut cfg = app_config.write();
            if (idx as usize) < cfg.rules.len() {
                cfg.rules[idx as usize] = rule;
                let _ = cfg.save();
                
                // Update live engine
                *re.write() = RuleEngine::new(cfg.rules.clone(), cfg.default_action.clone());
                
                // Refresh UI list
                if let Some(ui) = ui_handle.upgrade() {
                    let ui_rules: Vec<RuleData> = cfg.rules.iter().map(rule_to_ui).collect();
                    ui.set_rules_list(ModelRc::from(std::rc::Rc::new(VecModel::from(ui_rules))));
                }
                info!("Rule updated");
            }
        }
    });

    ui.on_add_rule({
        let app_config = app_config.clone();
        let re = rule_engine.clone();
        let ui_handle = ui_handle.clone();
        move |rule_data| {
            if rule_data.name.is_empty() && rule_data.process_name.is_empty() && rule_data.target_ips.is_empty() && rule_data.target_ports.is_empty() {
                warn!("Ignoring empty rule addition");
                return;
            }
            let rule = ui_to_rule(rule_data);
            let mut cfg = app_config.write();
            
            // Check for duplicate
            if cfg.rules.iter().any(|r| r.name == rule.name && r.process_name == rule.process_name && r.target_ips == rule.target_ips && r.target_ports == rule.target_ports) {
                warn!("Ignoring duplicate rule addition");
                return;
            }

            cfg.rules.push(rule);
            let _ = cfg.save();
            
            // Update live engine
            *re.write() = RuleEngine::new(cfg.rules.clone(), cfg.default_action.clone());
            
            // Refresh UI list
            if let Some(ui) = ui_handle.upgrade() {
                let ui_rules: Vec<RuleData> = cfg.rules.iter().map(rule_to_ui).collect();
                ui.set_rules_list(ModelRc::from(std::rc::Rc::new(VecModel::from(ui_rules))));
            }
            info!("Rule added");
        }
    });

    ui.on_toggle_rule_enabled({
        let app_config = app_config.clone();
        let re = rule_engine.clone();
        let ui_handle = ui_handle.clone();
        move |idx, enabled| {
            let mut cfg = app_config.write();
            if (idx as usize) < cfg.rules.len() {
                cfg.rules[idx as usize].enabled = enabled;
                let _ = cfg.save();
                
                // Update live engine
                *re.write() = RuleEngine::new(cfg.rules.clone(), cfg.default_action.clone());
                
                // Refresh UI list
                if let Some(ui) = ui_handle.upgrade() {
                    let ui_rules: Vec<RuleData> = cfg.rules.iter().map(rule_to_ui).collect();
                    ui.set_rules_list(ModelRc::from(std::rc::Rc::new(VecModel::from(ui_rules))));
                }
                info!("Rule enabled status toggled: {}", enabled);
            }
        }
    });

    ui.on_remove_rule({
        let app_config = app_config.clone();
        let re = rule_engine.clone();
        let ui_handle = ui_handle.clone();
        move |idx| {
            let mut cfg = app_config.write();
            if (idx as usize) < cfg.rules.len() {
                cfg.rules.remove(idx as usize);
                let _ = cfg.save();
                
                // Update live engine
                *re.write() = RuleEngine::new(cfg.rules.clone(), cfg.default_action.clone());
                
                // Refresh UI list
                if let Some(ui) = ui_handle.upgrade() {
                    let ui_rules: Vec<RuleData> = cfg.rules.iter().map(rule_to_ui).collect();
                    ui.set_rules_list(ModelRc::from(std::rc::Rc::new(VecModel::from(ui_rules))));
                }
                info!("Rule removed");
            }
        }
    });

    ui.on_default_rule_changed({
        let re_c = rule_engine.clone();
        let config_c = app_config.clone();
        move |action| {
            let new_action = match action.as_str() {
                "Proxy" => RuleAction::DefaultProxy,
                "Direct" => RuleAction::Direct,
                "Block" => RuleAction::Block,
                _ => RuleAction::Direct,
            };
            re_c.write().default_action = new_action.clone();
            let mut conf = config_c.write();
            conf.default_action = new_action;
            let _ = conf.save();
            info!("Default rule changed to: {:?}", conf.default_action);
        }
    });

    let sm_bg = session_manager.clone();
    let re_bg = rule_engine.clone();
    let fm_bg = fake_ip_manager.clone();
    let ui_bg = ui_handle.clone();
    let config_bg = app_config.clone();
    let running_bg = engine_running.clone();

    // --- UI Watch Channel (created on UI thread, passed to engine) ---
    // The background engine writes snapshots here; a Slint Timer on the UI
    // thread reads them. Only the latest snapshot is kept — no queue buildup.
    let (ui_snap_tx, ui_snap_rx) = tokio::sync::watch::channel::<Option<(Vec<TrafficEntry>, i32, bool)>>(None);

    // --- Slint Timer: runs on UI thread, safe to call set_* directly ---
    {
        let ui_snap_rx = std::sync::Arc::new(std::sync::Mutex::new(ui_snap_rx));
        let ui_h_timer = ui_handle.clone();
        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_millis(1000),
            move || {
                let mut rx = ui_snap_rx.lock().unwrap();
                if rx.has_changed().unwrap_or(false) {
                    let val = rx.borrow_and_update().clone();
                    if let Some((entries, conn_count, is_clear)) = val {
                        if let Some(ui) = ui_h_timer.upgrade() {
                            if is_clear {
                                ui.set_traffic_rows(ModelRc::from(std::rc::Rc::new(VecModel::from(Vec::<TrafficEntry>::new()))));
                                ui.set_active_connections(0);
                            } else {
                                ui.set_traffic_rows(ModelRc::from(std::rc::Rc::new(VecModel::from(entries))));
                                ui.set_active_connections(conn_count);
                            }
                        }
                    }
                }
            },
        );
        Box::leak(Box::new(timer));
    }

    tokio::spawn(async move {
        if let Err(e) = run_core_engine(sm_bg, re_bg, fm_bg, ui_bg, config_bg, running_bg, ui_snap_tx).await {
            error!("Core engine error: {:?}", e);
        }
    });

    let cfg_tcp = app_config.clone();
    let sm_tcp = session_manager.clone();
    let fm_tcp = fake_ip_manager.clone();
    tokio::spawn(async move {
        let l_port = cfg_tcp.read().local_proxy_port;
        let _ = run_tcp_proxy(l_port, cfg_tcp, sm_tcp, fm_tcp).await;
    });

    let cfg_udp = app_config.clone();
    let sm_udp = session_manager.clone();
    let fm_udp = fake_ip_manager.clone();
    tokio::spawn(async move {
        let l_port = cfg_udp.read().local_udp_relay_port;
        let _ = run_udp_relay(l_port, cfg_udp, sm_udp, fm_udp).await;
    });

    let _ = ui.run();
    
    // Prevent main from exiting so the tray icon stays alive
    info!("UI event loop finished, entering background mode...");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn rule_to_ui(r: &Rule) -> RuleData {
    RuleData {
        name: r.name.clone().into(),
        process_name: r.process_name.clone().unwrap_or_default().into(),
        target_ips: r.target_ips.clone().unwrap_or_default().join(",").into(),
        target_ports: r.target_ports.clone().map(|p| p.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")).unwrap_or_default().into(),
        protocol: match r.protocol {
            Protocol::Tcp => "TCP".into(),
            Protocol::Udp => "UDP".into(),
            Protocol::Both => "Both".into(),
        },
        action: match &r.action {
            RuleAction::Proxy(_) | RuleAction::DefaultProxy => "Proxy".into(),
            RuleAction::Direct => "Direct".into(),
            RuleAction::Block => "Block".into(),
        },
        proxy_name: match &r.action {
            RuleAction::Proxy(name) => name.clone().into(),
            _ => "Default".into(),
        },
        enabled: r.enabled,
        // ignore proc_regex
    }
}

fn proxy_to_ui(p: &ProxyConfig) -> ProxyData {
    ProxyData {
        name: p.name.clone().into(),
        host: p.host.clone().into(),
        port: p.port.to_string().into(),
        protocol: p.protocol.as_str().into(),
    }
}

fn ui_to_rule(d: RuleData) -> Rule {
    Rule {
        name: d.name.to_string(),
        process_name: if d.process_name.is_empty() { None } else { Some(d.process_name.to_string()) },
        target_ips: if d.target_ips.is_empty() { None } else { Some(d.target_ips.split(',').map(|s| s.trim().to_string()).collect()) },
        target_ports: if d.target_ports.is_empty() { None } else { Some(d.target_ports.split(',').filter_map(|s| s.trim().parse().ok()).collect()) },
        protocol: match d.protocol.as_str() {
            "TCP" => Protocol::Tcp,
            "UDP" => Protocol::Udp,
            _ => Protocol::Both,
        },
        action: match d.action.as_str() {
            "Direct" => RuleAction::Direct,
            "Block" => RuleAction::Block,
            _ => if d.proxy_name.is_empty() || d.proxy_name == "Default" { 
                RuleAction::DefaultProxy 
            } else { 
                RuleAction::Proxy(d.proxy_name.to_string()) 
            },
        },
        enabled: d.enabled,
        proc_regex: None,
    }
}

async fn run_core_engine(
    sm: Arc<SessionManager>, 
    re: Arc<RwLock<RuleEngine>>, 
    fm: Arc<FakeIpManager>,
    ui_handle: slint::Weak<AppWindow>,
    config: Arc<RwLock<AppConfig>>,
    engine_running: Arc<std::sync::atomic::AtomicBool>,
    ui_snap_tx: tokio::sync::watch::Sender<Option<(Vec<TrafficEntry>, i32, bool)>>,
) -> Result<()> {
    // Use a BOUNDED channel to apply backpressure instead of unbounded queue growth
    let (tx, mut rx) = tokio::sync::mpsc::channel::<TrafficUpdateEvent>(64);

    // Background UI Sync Task — only computes data, sends to watch channel
    let sm_ui = sm.clone();
    let cfg_mon = config.clone();
    let er_ui = engine_running.clone();
    tokio::spawn(async move {
        let mut transient_events: Vec<(String, String, std::time::Instant)> = Vec::new();
        // Lower frequency to 1s to give UI thread more breath time
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(1000));
        let mut cleanup_counter: u32 = 0;
        let mut last_was_empty = true;
        
        loop {
            ticker.tick().await;
            
            // Drain all pending channel events in bulk (non-blocking)
            while let Ok(event) = rx.try_recv() {
                if event.action_display == "BLOCK" || event.action_display == "FAKE DNS" {
                    transient_events.push((
                        event.process_name,
                        event.dest_display,
                        event.start_time,
                    ));
                    // Keep transient events list very short to avoid UI bloat
                    if transient_events.len() > 10 {
                        transient_events.remove(0);
                    }
                }
            }
            
            // Periodic session cleanup
            cleanup_counter += 1;
            if cleanup_counter >= 15 { // Every 15s
                sm_ui.cleanup_stale(60);
                let now = std::time::Instant::now();
                transient_events.retain(|t| now.duration_since(t.2).as_secs() < 30);
                cleanup_counter = 0;
            }

            // Check if monitor is enabled
            let mon_enabled = cfg_mon.read().monitor_enabled;
            if !mon_enabled {
                continue;
            }
            
            let engine_active = er_ui.load(std::sync::atomic::Ordering::Relaxed);
            
            let mut active_sessions = sm_ui.get_all_sessions();
            let is_empty = active_sessions.is_empty() && transient_events.is_empty();
            
            if is_empty && last_was_empty && !engine_active {
                continue;
            }
            
            if is_empty {
                if !last_was_empty {
                    let _ = ui_snap_tx.send(Some((vec![], 0, true)));
                    last_was_empty = true;
                }
                continue;
            }

            // Calculate total connections before truncation
            let total_conn_count = (active_sessions.len() + transient_events.len()) as i32;

            // CRITICAL: Limit displayed rows to 40. 
            // Slint can struggle with layout/rendering of 100+ complex rows every second.
            if active_sessions.len() > 40 {
                // Sort by last activity or just take the most recent
                active_sessions.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));
                active_sessions.truncate(40);
            }

            let mut entries: Vec<TrafficEntry> = active_sessions.into_iter().map(|s| {
                TrafficEntry {
                    process_name: s.process_name.into(),
                    target: s.display_dest.into(),
                    time: format_duration(s.start_time).into(),
                    rule_proxy: s.action_display.into(),
                    sent: format_bytes(s.sent_bytes).into(),
                    received: format_bytes(s.recv_bytes).into(),
                    src_port: "".into(),
                }
            }).collect();
            
            for t in &transient_events {
                entries.push(TrafficEntry {
                    process_name: t.0.clone().into(),
                    target: t.1.clone().into(),
                    time: format_duration(t.2).into(),
                    rule_proxy: "BLOCK".into(),
                    sent: "0".into(),
                    received: "0".into(),
                    src_port: "".into(),
                });
            }
            
            // Final sort for the UI display
            entries.sort_by(|a, b| a.process_name.cmp(&b.process_name));
            last_was_empty = false;
            
            let _ = ui_snap_tx.send(Some((entries, total_conn_count, false)));
        }
    });
    info!("Starting WinDivert core engine...");
    let (l_tcp, l_udp) = {
        let cfg = config.read();
        (cfg.local_proxy_port, cfg.local_udp_relay_port)
    };

    let filter = format!(
        "(tcp and (outbound or (tcp.DstPort == {} or tcp.SrcPort == {}))) or (udp and (outbound or (udp.DstPort == {} or udp.SrcPort == {})))",
        l_tcp, l_tcp, l_udp, l_udp
    );

    debug!("Starting core engine with filter: {}", filter);

    let divert_result = WinDivert::<NetworkLayer>::network(&filter, 1000, WinDivertFlags::default());
    
    if let Err(e) = &divert_result {
        let err_msg = format!("Engine Error: {}", e);
        error!("{}", err_msg);
        let ui_weak = ui_handle.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let ui: AppWindow = ui;
                ui.set_status_text(slint::SharedString::from("Error: Admin Rights Required?"));
                ui.set_is_running(false);
            }
        });
        return Err(anyhow::anyhow!("WinDivert init failed: {:?}", e));
    }
    let divert = Arc::new(divert_result.unwrap());

    let num_threads = num_cpus::get().max(4);
    for i in 0..num_threads {
        let divert_c = divert.clone();
        let sm = sm.clone();
        let re = re.clone();
        let fm = fm.clone();
        let cfg_lock = config.clone();
        let is_running_atomic = engine_running.clone();
        let tx = tx.clone();

        task::spawn_blocking(move || {
            info!("INTERCEPTION THREAD #{} STARTING TO RECV...", i);
            let mut buffer = [0u8; 65535];
            loop {
                let is_running = is_running_atomic.load(std::sync::atomic::Ordering::SeqCst);

                match divert_c.recv(&mut buffer) {
                    Ok(packet) => {
                        if !is_running {
                            let _ = divert_c.send(&packet);
                            continue;
                        }

                        let addr = &packet.address;
                        let original_data = &packet.data;
                        let cfg = cfg_lock.read();
                        
                        let headers_res = PacketHeaders::from_ip_slice(original_data);
                        if let Err(_) = headers_res {
                            let _ = divert_c.send(&packet);
                            continue;
                        }
                        let headers = headers_res.unwrap();

                        let (is_udp, src_ip, src_port, dest_ip, dest_port) = match (&headers.net, &headers.transport) {
                            (Some(NetHeaders::Ipv4(ip_hdr, _)), Some(TransportHeader::Tcp(tcp_hdr))) => {
                                (false, Ipv4Addr::from(ip_hdr.source), tcp_hdr.source_port, Ipv4Addr::from(ip_hdr.destination), tcp_hdr.destination_port)
                            },
                            (Some(NetHeaders::Ipv4(ip_hdr, _)), Some(TransportHeader::Udp(udp_hdr))) => {
                                (true, Ipv4Addr::from(ip_hdr.source), udp_hdr.source_port, Ipv4Addr::from(ip_hdr.destination), udp_hdr.destination_port)
                            },
                            _ => { 
                                let _ = divert_c.send(&packet); continue; 
                            }
                        };

                        debug!("Packet Hit: {} {}[:{}] -> {}[:{}]", 
                            if addr.outbound() { "OUT" } else { "IN " },
                            src_ip, src_port, dest_ip, dest_port
                        );

                        let l_port = if is_udp { cfg.local_udp_relay_port } else { cfg.local_proxy_port };
                        
                        // --- LOCAL PROXY TRAFFIC HANDLING ---
                        // Check if this packet is from/to our local proxy server
                        // After redirection, packets to proxy have dest_port = l_port
                        // Packets from proxy have src_port = l_port
                        if addr.outbound() && src_port == l_port {
                            // This is a response from our proxy server, let it go to Restoration block
                            // Continue to Restoration block below
                        } else if !addr.outbound() && dest_port == l_port {
                            // This is a packet redirected TO our local proxy server
                            // Let it reach the listener
                            let _ = divert_c.send(&packet);
                            continue;
                        } else if src_ip.is_loopback() && dest_ip.is_loopback() {
                            // Internal loopback traffic not related to our proxy, pass through
                            let _ = divert_c.send(&packet);
                            continue;
                        }

                        // 1. Restoration (Proxy Server Response -> Client)
                        // This identifies packets sent BY our local proxy server (Outbound, from l_port)
                        if addr.outbound() && src_port == l_port {
                            if let Some(session) = sm.get_session(dest_port) {
                                let mut data = original_data.to_vec();
                                let ip_hdr_len = (data[0] & 0x0f) as usize * 4;

                                // Restore packet to look like it came from the original destination
                                // Original: Proxy(127.0.0.1:l_port) -> Client(src_ip:src_port)
                                // Restored: Remote(orig_dest_ip:orig_dest_port) -> Client(src_ip:src_port)
                                data[12..16].copy_from_slice(&session.orig_dest_ip.octets());  // Source IP = original destination IP
                                data[16..20].copy_from_slice(&session.src_ip.octets());        // Dest IP = original source IP (client)
                                data[ip_hdr_len..ip_hdr_len+2].copy_from_slice(&session.orig_dest_port.to_be_bytes());  // Source port = original destination port
                                data[ip_hdr_len+2..ip_hdr_len+4].copy_from_slice(&session.src_port.to_be_bytes());      // Dest port = original source port (client)
                                
                                calc_checksums(&mut data);
                                sm.update_traffic(dest_port, 0, original_data.len() as u64);
                                
                                info!("Packet Restored: IN {}[:{}] -> {}[:{}]", session.orig_dest_ip, session.orig_dest_port, session.src_ip, session.src_port);

                                // Important: Re-inject as INBOUND so the client application receives it
                                let mut final_addr = addr.clone();
                                final_addr.set_outbound(false);
                                let _ = divert_c.send(&WinDivertPacket { address: final_addr, data: Cow::Owned(data) });
                                continue;
                            }
                        }

                        // 2. Loopback/Inbound Handling
                        if !addr.outbound() {
                            // Check if this inbound packet belongs to an active session we are tracking
                            if let Some(_session) = sm.get_session(dest_port) {
                                let packet_len = original_data.len() as u64;
                                sm.update_traffic(dest_port, 0, packet_len);
                            }
                            
                            let _ = divert_c.send(&packet);
                            continue;
                        }

                        // 3. Outbound Redirection (Client -> Remote)
                        if addr.outbound() {
                            // Rule matching (moved up to support DNS logging)
                            let mut pid_val = None;
                            let pid_res = if is_udp { get_pid_from_udp_connection(src_ip, src_port) } else { get_pid_from_tcp_connection(src_ip, src_port) };
                            if let Some(p) = pid_res { pid_val = Some(p); }
                            
                            let process_name = pid_res.and_then(get_process_name).unwrap_or_else(|| "unknown".into());
                            let display_process_name = if let Some(p) = pid_val {
                                format!("{} ({})", process_name, p)
                            } else {
                                process_name.clone()
                            };

                            let l_port = if is_udp { cfg.local_udp_relay_port } else { cfg.local_proxy_port };
                            
                            // --- PREVENT INFINITE LOOP ---
                            // If this packet is already going TO our local proxy port, let it pass.
                            if dest_port == l_port {
                                if let Some(_session) = sm.get_session(src_port) {
                                    let _ = divert_c.send(&packet);
                                    continue;
                                }
                            }

                            // Exclude ourselves
                            let lower_proc = process_name.to_lowercase();
                            if lower_proc.contains("proxybridge") {
                                let _ = divert_c.send(&packet);
                                continue;
                            }

                            // 3. DNS Redirect (Fake IP)
                            if is_udp && dest_port == 53 && cfg.fake_ip_enabled {
                                if let Some(fake_resp) = handle_dns_query(original_data, &fm) {
                                    let mut final_addr = addr.clone();
                                    final_addr.set_outbound(false);
                                    let _ = divert_c.send(&WinDivertPacket { address: final_addr, data: Cow::Owned(fake_resp) });
                                    
                                    let _ = tx.try_send(TrafficUpdateEvent {
                                        process_name: display_process_name.clone(),
                                        dest_display: "DNS -> FakeIP".into(),
                                        start_time: std::time::Instant::now(),
                                        action_display: "FAKE DNS".into(),
                                    });
                                    continue;
                                }
                            }

                            let is_fake = fm.is_fake_ip(dest_ip);
                            let action = if is_fake { RuleAction::DefaultProxy } else { re.read().match_rule(&process_name, dest_ip, dest_port, is_udp) };
                            let display_dest = if is_fake { 
                                if let Some(d) = fm.get_domain(dest_ip) {
                                    format!("{}:{}", d, dest_port)
                                } else {
                                    // Fallback text if domain mapping is missing
                                    format!("{}:{} (FakeIP)", dest_ip, dest_port)
                                }
                            } else { 
                                format!("{}:{}", dest_ip, dest_port)
                            };

                            match &action {
                                RuleAction::Proxy(_) | RuleAction::DefaultProxy => {
                                    let p_name = if let RuleAction::Proxy(ref n) = action {
                                        Some(n.clone())
                                    } else {
                                        None
                                    };
                                    let display_name = p_name.as_deref().unwrap_or("Default").to_string();

                                     let packet_len = original_data.len() as u64;
                                     if let Some(_) = sm.get_session(src_port) {
                                         sm.update_traffic(src_port, packet_len, 0);
                                     } else {
                                         sm.add_session(src_port, SessionInfo { 
                                             src_ip, src_port, orig_dest_ip: dest_ip, orig_dest_port: dest_port, 
                                             last_activity: std::time::Instant::now(), start_time: std::time::Instant::now(),
                                             sent_bytes: packet_len, recv_bytes: 0, 
                                             proxy_name: p_name, 
                                             process_name: display_process_name.clone(),
                                             display_dest: display_dest.clone(),
                                             action_display: format!("Proxy ({})", display_name),
                                         });
                                     };

                                      if cfg.logging_enabled {
                                          info!("Packet Redirect: {} -> {} via {}", display_process_name, display_dest, display_name);
                                      }

                                    let mut data = original_data.to_vec();
                                    let ip_hdr_len = (data[0] & 0x0f) as usize * 4;

                                    // Redirect to local proxy - Match C implementation behavior
                                    // IP header: bytes 12-15 = source IP, bytes 16-19 = dest IP
                                    // TCP/UDP header: bytes 0-1 = source port, bytes 2-3 = dest port
                                    let orig_src_ip = data[12..16].to_vec();  // Save original source IP
                                    let orig_dst_ip = data[16..20].to_vec();  // Save original dest IP
                                    // Keep original source port unchanged so proxy can identify the session
                                    
                                    // C implementation logic:
                                    // 1. Swap source and dest IP
                                    // 2. Set dest port to local proxy port
                                    // 3. Keep source port unchanged (this is the key for session lookup)
                                    data[12..16].copy_from_slice(&orig_dst_ip); // Source IP = original destination IP
                                    data[16..20].copy_from_slice(&orig_src_ip); // Dest IP = original source IP
                                    // Source port stays the same (original source port) - this is crucial for session lookup
                                    data[ip_hdr_len+2..ip_hdr_len+4].copy_from_slice(&l_port.to_be_bytes()); // Dest port = local proxy port
                                    
                                    // Fix checksums manually
                                    calc_checksums(&mut data);

                                    // MUST set outbound to false for local listener to pick it up
                                    let mut final_addr = addr.clone();
                                    final_addr.set_outbound(false);
                                    let _ = divert_c.send(&WinDivertPacket { address: final_addr, data: Cow::Owned(data) });
                                    continue;
                                },
                                RuleAction::Block => {
                                    if cfg.logging_enabled {
                                        info!("Packet Blocked: {} -> {}", display_process_name, display_dest);
                                    }
                                     let _ = tx.try_send(TrafficUpdateEvent {
                                        process_name: display_process_name, dest_display: display_dest,
                                        start_time: std::time::Instant::now(), action_display: "BLOCK".into(),
                                    });
                                    continue;
                                },
                                RuleAction::Direct => {
                                     let packet_len = original_data.len() as u64;
                                     if let Some(_) = sm.get_session(src_port) {
                                         sm.update_traffic(src_port, packet_len, 0);
                                     } else {
                                         sm.add_session(src_port, SessionInfo { 
                                             src_ip, src_port, orig_dest_ip: dest_ip, orig_dest_port: dest_port, 
                                             last_activity: std::time::Instant::now(), start_time: std::time::Instant::now(),
                                             sent_bytes: packet_len, recv_bytes: 0, proxy_name: None, 
                                             process_name: display_process_name.clone(),
                                             display_dest: display_dest.clone(),
                                             action_display: "Direct".into(),
                                         });
                                     };
                                     
                                     if cfg.logging_enabled {
                                         info!("Packet Direct: {} -> {}", display_process_name, display_dest);
                                     }
                                }
                            }
                        }

                        // Default Passthrough
                        let _ = divert_c.send(&packet);
                    },
                    Err(_) => break,
                }
            }
        });
    }
    std::future::pending::<()>().await;
    Ok(())
}

fn handle_dns_query(data: &[u8], fm: &FakeIpManager) -> Option<Vec<u8>> {
    let headers = PacketHeaders::from_ip_slice(data).ok()?;
    let payload = headers.payload.slice();
    if payload.len() < 12 { return None; }
    let transaction_id = &payload[0..2];
    let mut domain = String::new();
    let mut pos = 12;
    loop {
        if pos >= payload.len() { return None; }
        let len = payload[pos] as usize;
        if len == 0 { break; }
        pos += 1;
        if pos + len > payload.len() { 
            warn!("DNS parse fail: domain length overflow");
            return None; 
        }
        if !domain.is_empty() { domain.push('.'); }
        domain.push_str(std::str::from_utf8(&payload[pos..pos+len]).ok()?);
        pos += len;
    }
    
    info!("Intercepted DNS query for: {}", domain);
    let fake_ip = fm.get_or_assign_ip(&domain);
    info!("Assigned Fake IP: {} for {}", fake_ip, domain);
    
    let mut dns_resp = Vec::new();
    dns_resp.extend_from_slice(transaction_id);
    dns_resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    let q_end = pos + 5;
    if q_end > payload.len() { return None; }
    dns_resp.extend_from_slice(&payload[12..q_end]);
    dns_resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04]);
    dns_resp.extend_from_slice(&fake_ip.octets());
    let mut final_pkt = Vec::new();
    if let Some(NetHeaders::Ipv4(ip_h, _)) = &headers.net {
        let mut ip_resp = ip_h.clone();
        std::mem::swap(&mut ip_resp.source, &mut ip_resp.destination);
        ip_resp.write(&mut final_pkt).unwrap();
        
        let udp_src_port = match &headers.transport {
            Some(TransportHeader::Udp(h)) => h.source_port,
            _ => 0
        };
        if udp_src_port == 0 { return None; }
        
        let udp_resp = UdpHeader::with_ipv4_checksum(53, udp_src_port, &ip_resp, &dns_resp).unwrap();
        udp_resp.write(&mut final_pkt).unwrap();
        final_pkt.extend_from_slice(&dns_resp);
        return Some(final_pkt);
    }
    None
}

fn format_bytes(bytes: u64) -> String {
    if bytes == 0 { return "0".into(); }
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn format_duration(start: std::time::Instant) -> String {
    let secs = start.elapsed().as_secs();
    if secs < 1 {
        return "< 1 sec".into();
    }
    let mins = secs / 60;
    let s = secs % 60;
    if mins > 0 {
        format!("{:02}:{:02}", mins, s)
    } else {
        format!("{}s", s)
    }
}

#[allow(dead_code)]
fn get_process_name_for_rule(pid: u32) -> Option<String> {
    get_process_name(pid)
}

fn calc_checksums(data: &mut [u8]) {
    let ip_hdr_len = (data[0] & 0x0f) as usize * 4;
    if data.len() < ip_hdr_len { return; }
    
    let proto = data[9];
    let is_udp = proto == 17;
    let is_tcp = proto == 6;

    // 1. IP Checksum
    data[10..12].copy_from_slice(&[0, 0]);
    let mut sum = 0u32;
    for i in (0..ip_hdr_len).step_by(2) {
        sum += u16::from_be_bytes([data[i], data[i+1]]) as u32;
    }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    let ip_cksum = !(sum as u16);
    data[10..12].copy_from_slice(&ip_cksum.to_be_bytes());
    
    // 2. Transport Checksum
    let transport_offset = ip_hdr_len;
    if is_tcp && data.len() >= transport_offset + 20 {
        data[transport_offset + 16..transport_offset + 18].copy_from_slice(&[0, 0]);
        let mut sum = 0u32;
        // Pseudo-header
        for i in (12..20).step_by(2) { sum += u16::from_be_bytes([data[i], data[i+1]]) as u32; }
        sum += proto as u32;
        sum += (data.len() - transport_offset) as u32;
        // Segment
        for i in (transport_offset..data.len()).step_by(2) {
            if i + 1 < data.len() {
                sum += u16::from_be_bytes([data[i], data[i+1]]) as u32;
            } else {
                sum += (data[i] as u32) << 8;
            }
        }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
        let cksum = !(sum as u16);
        data[transport_offset + 16..transport_offset + 18].copy_from_slice(&cksum.to_be_bytes());
    } else if is_udp && data.len() >= transport_offset + 8 {
        data[transport_offset + 6..transport_offset + 8].copy_from_slice(&[0, 0]);
        let mut sum = 0u32;
        // Pseudo-header
        for i in (12..20).step_by(2) { sum += u16::from_be_bytes([data[i], data[i+1]]) as u32; }
        sum += proto as u32;
        sum += (data.len() - transport_offset) as u32;
        // Segment
        for i in (transport_offset..data.len()).step_by(2) {
            if i + 1 < data.len() {
                sum += u16::from_be_bytes([data[i], data[i+1]]) as u32;
            } else {
                sum += (data[i] as u32) << 8;
            }
        }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
        let mut cksum = !(sum as u16);
        if cksum == 0 { cksum = 0xffff; }
        data[transport_offset + 6..transport_offset + 8].copy_from_slice(&cksum.to_be_bytes());
    }
}

fn find_main_window_handle() -> Option<HWND> {
    let window_title = CString::new("ProxyBridge High Performance Rust").ok()?;
    let hwnd_result = unsafe { 
        FindWindowA(None, PCSTR(window_title.as_ptr() as *const u8)) 
    };
    
    match hwnd_result {
        Ok(hwnd) if !hwnd.0.is_null() => Some(hwnd),
        _ => None,
    }
}
