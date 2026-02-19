use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID};
use windows::Win32::Networking::WinSock::AF_INET;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameA};
use lazy_static::lazy_static;

lazy_static! {
    static ref PID_CACHE: Mutex<HashMap<(Ipv4Addr, u16, bool), u32>> = Mutex::new(HashMap::new());
}

pub fn get_pid_from_tcp_connection(src_ip: Ipv4Addr, src_port: u16) -> Option<u32> {
    get_pid_cached(src_ip, src_port, false)
}

pub fn get_pid_from_udp_connection(src_ip: Ipv4Addr, src_port: u16) -> Option<u32> {
    get_pid_cached(src_ip, src_port, true)
}

fn get_pid_cached(src_ip: Ipv4Addr, src_port: u16, is_udp: bool) -> Option<u32> {
    if let Ok(cache) = PID_CACHE.lock() {
        if let Some(&pid) = cache.get(&(src_ip, src_port, is_udp)) {
            return Some(pid);
        }
    }
    
    let pid = if is_udp {
        lookup_udp(src_ip, src_port)
    } else {
        lookup_tcp(src_ip, src_port)
    };

    if let Some(p) = pid {
        if let Ok(mut cache) = PID_CACHE.lock() {
            // Prevent indefinite growth (e.g., from unique source ports)
            if cache.len() > 10000 {
                cache.clear();
            }
            cache.insert((src_ip, src_port, is_udp), p);
        }
    }
    pid
}

fn lookup_tcp(src_ip: Ipv4Addr, src_port: u16) -> Option<u32> {
    let mut dw_size = 0;
    unsafe {
        let _ = GetExtendedTcpTable(None, &mut dw_size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        let mut buffer = vec![0u8; dw_size as usize];
        if GetExtendedTcpTable(Some(buffer.as_mut_ptr() as *mut _), &mut dw_size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0) == 0 {
            let num_entries = *(buffer.as_ptr() as *const u32);
            let ptr = buffer.as_ptr().add(4) as *const TcpRow;
            for i in 0..num_entries {
                let row = *ptr.add(i as usize);
                // Allow binding to specific IP OR 0.0.0.0 (Any)
                if (Ipv4Addr::from(row.dw_local_addr.to_be()) == src_ip || row.dw_local_addr == 0) 
                    && u16::from_be(row.dw_local_port as u16) == src_port {
                    return Some(row.dw_owning_pid);
                }
            }
        }
    }
    None
}

fn lookup_udp(src_ip: Ipv4Addr, src_port: u16) -> Option<u32> {
    let mut dw_size = 0;
    unsafe {
        let _ = GetExtendedUdpTable(None, &mut dw_size, false, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0);
        let mut buffer = vec![0u8; dw_size as usize];
        if GetExtendedUdpTable(Some(buffer.as_mut_ptr() as *mut _), &mut dw_size, false, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0) == 0 {
            let num_entries = *(buffer.as_ptr() as *const u32);
            let ptr = buffer.as_ptr().add(4) as *const UdpRow;
            for i in 0..num_entries {
                let row = *ptr.add(i as usize);
                if (Ipv4Addr::from(row.dw_local_addr.to_be()) == src_ip || row.dw_local_addr == 0) && u16::from_be(row.dw_local_port as u16) == src_port {
                    return Some(row.dw_owning_pid);
                }
            }
        }
    }
    None
}

pub fn get_process_name(pid: u32) -> Option<String> {
    if pid == 0 { return None; }
    if pid == 4 { return Some("System".to_string()); }

    unsafe {
        let handle_res = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        match handle_res {
            Ok(handle) => {
                let mut buffer = [0u8; 512];
                let mut size = buffer.len() as u32;
                let res = QueryFullProcessImageNameA(handle, windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0), windows::core::PSTR(buffer.as_mut_ptr()), &mut size);
                let _ = CloseHandle(handle);
                
                if res.is_ok() {
                    let path = std::str::from_utf8(&buffer[..size as usize]).ok()?;
                    let name = path.rsplit('\\').next()?.to_string();
                    return Some(name);
                } else {
                    tracing::debug!("QueryFullProcessImageNameA failed for PID {}", pid);
                }
            },
            Err(e) => {
                tracing::debug!("OpenProcess failed for PID {}: {:?}", pid, e);
            }
        }
    }
    None
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TcpRow {
    dw_state: u32,
    dw_local_addr: u32,
    dw_local_port: u32,
    dw_remote_addr: u32,
    dw_remote_port: u32,
    dw_owning_pid: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct UdpRow {
    dw_local_addr: u32,
    dw_local_port: u32,
    dw_owning_pid: u32,
}
