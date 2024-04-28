use frida_gum::interceptor::Interceptor;
use frida_gum::{Gum, Module, NativePointer};

use lazy_static::lazy_static;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::mem::{self, size_of, transmute};
use std::net::Ipv4Addr;
use std::sync::Mutex;
use windows::core::{GUID, PCSTR, PCWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Networking::WinSock::{
    ADDRINFOA, ADDRINFOEXA, ADDRINFOEXW, ADDRINFOW, AF_INET, LPLOOKUPSERVICE_COMPLETION_ROUTINE,
    SOCKADDR, SOCKADDR_IN, TIMEVAL,
};
use windows::Win32::System::IO::OVERLAPPED;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    pub static ref ENABLED: Mutex<UnsafeCell<bool>> = Mutex::new(UnsafeCell::new(false));
    static ref ORIGINAL1: Mutex<UnsafeCell<Option<GetAddrInfoAFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref ORIGINAL2: Mutex<UnsafeCell<Option<GetAddrInfoWFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref ORIGINAL3: Mutex<UnsafeCell<Option<GetAddrInfoExAFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref ORIGINAL4: Mutex<UnsafeCell<Option<GetAddrInfoExWFunc>>> =
        Mutex::new(UnsafeCell::new(None));
}

static mut TARGET1: Option<NativePointer> = None;
static mut TARGET2: Option<NativePointer> = None;
static mut TARGET3: Option<NativePointer> = None;
static mut TARGET4: Option<NativePointer> = None;

type GetAddrInfoAFunc = unsafe extern "system" fn(
    pnodename: PCSTR,
    pservicename: PCSTR,
    phints: *const ADDRINFOA,
    ppresult: *mut *mut ADDRINFOA,
) -> i32;

type GetAddrInfoWFunc = unsafe extern "system" fn(
    pnodename: PCWSTR,
    pservicename: PCWSTR,
    phints: *const ADDRINFOW,
    ppresult: *mut *mut ADDRINFOW,
) -> i32;

type GetAddrInfoExAFunc = unsafe extern "system" fn(
    pname: PCSTR,
    pservicename: PCSTR,
    dwnamespace: u32,
    lpnspid: *const GUID,
    hints: *const ADDRINFOEXA,
    ppresult: *mut *mut ADDRINFOEXA,
    timeout: *const TIMEVAL,
    lpoverlapped: *const OVERLAPPED,
    lpcompletionroutine: LPLOOKUPSERVICE_COMPLETION_ROUTINE,
    lpnamehandle: *mut HANDLE,
) -> i32;

type GetAddrInfoExWFunc = unsafe extern "system" fn(
    pname: PCWSTR,
    pservicename: PCWSTR,
    dwnamespace: u32,
    lpnspid: *const GUID,
    hints: *const ADDRINFOEXW,
    ppresult: *mut *mut ADDRINFOEXW,
    timeout: *const TIMEVAL,
    lpoverlapped: *const OVERLAPPED,
    lpcompletionroutine: LPLOOKUPSERVICE_COMPLETION_ROUTINE,
    lphandle: *mut HANDLE,
) -> i32;

unsafe fn lookup(name: &str) -> Option<SOCKADDR> {
    let ipv4 = if name.eq("pixiv.net") {
        Some(Ipv4Addr::new(210, 140, 92, 183))
    } else if name.eq("www.pixiv.net") {
        Some(Ipv4Addr::new(210, 140, 92, 183))
    } else if name.ends_with(".pixiv.net") {
        Some(Ipv4Addr::new(104, 18, 42, 239))
    } else if name.eq("www.recaptcha.net") {
        Some(Ipv4Addr::new(142, 250, 191, 67))
    } else if name.ends_with("pximg.net") {
        Some(Ipv4Addr::new(210, 140, 139, 131))
    } else {
        None
    };
    if let Some(ipv4) = ipv4 {
        let addr = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: transmute(u32::from_le_bytes(ipv4.octets())),
            sin_port: 0,
            sin_zero: mem::zeroed(),
        };
        return Some(transmute(addr));
    }
    None
}

unsafe extern "system" fn detour1(
    pnodename: PCSTR,
    pservicename: PCSTR,
    phints: *const ADDRINFOA,
    ppresult: *mut *mut ADDRINFOA,
) -> i32 {
    unsafe {
        if *ENABLED.lock().unwrap().get_mut() {
            let name = pnodename.to_string().unwrap();
            if let Some(ip) = lookup(name.as_str()) {
                let hints = *phints;
                let mut addr_info = Box::new(hints.clone());
                let ip = Box::new(ip);
                addr_info.ai_addrlen = size_of::<SOCKADDR>();
                addr_info.ai_addr = Box::leak(ip);
                *ppresult = Box::leak(addr_info);
                return 0;
            }
        }
    }
    return ORIGINAL1.lock().unwrap().get_mut().unwrap()(pnodename, pservicename, phints, ppresult);
}

unsafe extern "system" fn detour4(
    pname: PCWSTR,
    pservicename: PCWSTR,
    dwnamespace: u32,
    lpnspid: *const GUID,
    hints: *const ADDRINFOEXW,
    ppresult: *mut *mut ADDRINFOEXW,
    timeout: *const TIMEVAL,
    lpoverlapped: *const OVERLAPPED,
    lpcompletionroutine: LPLOOKUPSERVICE_COMPLETION_ROUTINE,
    lphandle: *mut HANDLE,
) -> i32 {
    unsafe {
        if *ENABLED.lock().unwrap().get_mut() {
            log::info!("enter ws2 native dns detour");
            let name = pname.to_string().unwrap();
            if let Some(ip) = lookup(name.as_str()) {
                let hints = *hints;
                let mut addr_info = Box::new(hints.clone());
                let ip = Box::new(ip);
                addr_info.ai_addrlen = size_of::<SOCKADDR>();
                addr_info.ai_addr = Box::leak(ip);
                *ppresult = Box::leak(addr_info);
                return 0;
            }
        }
    }
    return ORIGINAL4.lock().unwrap().get_mut().unwrap()(
        pname,
        pservicename,
        dwnamespace,
        lpnspid,
        hints,
        ppresult,
        timeout,
        lpoverlapped,
        lpcompletionroutine,
        lphandle,
    );
}

pub fn install(auto_enable: bool) {
    eventlog::init("Pixeval.Bypass", log::Level::Info).ok();
    let mut interceptor = Interceptor::obtain(&GUM);
    interceptor.begin_transaction();
    unsafe {
        TARGET1 = Module::find_export_by_name(Some("ws2_32"), "getaddrinfo");
        TARGET2 = Module::find_export_by_name(Some("ws2_32"), "GetAddrInfoW");
        TARGET3 = Module::find_export_by_name(Some("ws2_32"), "GetAddrInfoExA");
        TARGET4 = Module::find_export_by_name(Some("ws2_32"), "GetAddrInfoExW");
        *ORIGINAL1.lock().unwrap().get_mut() = Some(transmute(
            interceptor
                .replace_fast(TARGET1.unwrap(), NativePointer(detour1 as *mut c_void))
                .unwrap()
                .0,
        ));
        *ORIGINAL4.lock().unwrap().get_mut() = Some(transmute(
            interceptor
                .replace_fast(TARGET4.unwrap(), NativePointer(detour4 as *mut c_void))
                .unwrap()
                .0,
        ));
    }
    interceptor.end_transaction();
    *ENABLED.lock().unwrap().get_mut() = auto_enable;
    log::info!("ws2 native dns hook installed");
}

pub fn remove() {
    let mut interceptor = Interceptor::obtain(&GUM);
    interceptor.begin_transaction();
    unsafe {
        interceptor.revert(TARGET1.unwrap());
    }
    interceptor.end_transaction();
}
