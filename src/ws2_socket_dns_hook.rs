use frida_gum::interceptor::Interceptor;
use frida_gum::{Gum, Module, NativePointer};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;
use lazy_static::lazy_static;
use std::cell::UnsafeCell;
use std::ffi::{c_char, c_void, CStr};
use std::mem::{self, transmute};
use std::net::IpAddr;
use std::sync::Mutex;
use windows_sys::core::PCSTR;
use windows_sys::Win32::Networking::WinSock::{
    ADDRINFOA, AF_INET, LPWSAOVERLAPPED_COMPLETION_ROUTINE, SOCKADDR, SOCKADDR_IN, SOCKET, WSABUF,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    pub static ref ENABLED: Mutex<UnsafeCell<bool>> = Mutex::new(UnsafeCell::new(false));
    static ref ORIGINAL1: Mutex<UnsafeCell<Option<WSASendToFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref ORIGINAL2: Mutex<UnsafeCell<Option<WSARecvFromFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref RESOLVER: Resolver =
        Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();
}

static mut TARGET1: Option<NativePointer> = None;
static mut TARGET2: Option<NativePointer> = None;

type WSASendToFunc = unsafe extern "system" fn(
    s: SOCKET,
    lpbuffers: *const WSABUF,
    dwbuffercount: u32,
    lpnumberofbytessent: *mut u32,
    dwflags: u32,
    lpto: *const SOCKADDR,
    itolen: i32,
    lpoverlapped: *mut OVERLAPPED,
    lpcompletionroutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32;

type WSARecvFromFunc = unsafe extern "system" fn(
    s: SOCKET,
    lpbuffers: *const WSABUF,
    dwbuffercount: u32,
    lpnumberofbytesrecvd: *mut u32,
    lpflags: *mut u32,
    lpfrom: *mut SOCKADDR,
    lpfromlen: *mut i32,
    lpoverlapped: *mut OVERLAPPED,
    lpcompletionroutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32;

unsafe fn lookup(name: &str) -> SOCKADDR {
    let response = RESOLVER.lookup_ip(name).unwrap();
    let address = response.iter().next().expect("no addresses returned!");
    let ipv4 = match address {
        IpAddr::V4(ipv4) => Some(ipv4),
        _ => None,
    };
    let addr = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_addr: transmute(u32::from_le_bytes(ipv4.unwrap().octets())),
        sin_port: 0,
        sin_zero: mem::zeroed(),
    };
    transmute(addr)
}

unsafe extern "system" fn detour1(
    s: SOCKET,
    lpbuffers: *const WSABUF,
    dwbuffercount: u32,
    lpnumberofbytessent: *mut u32,
    dwflags: u32,
    lpto: *const SOCKADDR,
    itolen: i32,
    lpoverlapped: *mut OVERLAPPED,
    lpcompletionroutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    unsafe {
        if *ENABLED.lock().unwrap().get_mut() {
            return 0;
        } else {
            return ORIGINAL1.lock().unwrap().get_mut().unwrap()(
                s,
                lpbuffers,
                dwbuffercount,
                lpnumberofbytessent,
                dwflags,
                lpto,
                itolen,
                lpoverlapped,
                lpcompletionroutine,
            );
        }
    }
}

unsafe extern "system" fn detour2(
    s: SOCKET,
    lpbuffers: *const WSABUF,
    dwbuffercount: u32,
    lpnumberofbytesrecvd: *mut u32,
    lpflags: *mut u32,
    lpfrom: *mut SOCKADDR,
    lpfromlen: *mut i32,
    lpoverlapped: *mut OVERLAPPED,
    lpcompletionroutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    unsafe {
        if *ENABLED.lock().unwrap().get_mut() {
            return 0;
        } else {
            return ORIGINAL2.lock().unwrap().get_mut().unwrap()(
                s,
                lpbuffers,
                dwbuffercount,
                lpnumberofbytesrecvd,
                lpflags,
                lpfrom,
                lpfromlen,
                lpoverlapped,
                lpcompletionroutine,
            );
        }
    }
}

pub fn install(auto_enable: bool) {
    eventlog::init("Pixeval.Bypass", log::Level::Trace).ok();
    let mut interceptor = Interceptor::obtain(&GUM);
    interceptor.begin_transaction();
    unsafe {
        TARGET1 = Module::find_export_by_name(Some("ws2_32"), "WSASendToFunc");
        TARGET2 = Module::find_export_by_name(Some("ws2_32"), "WSARecvFromFunc");
        *ORIGINAL1.lock().unwrap().get_mut() = Some(transmute(
            interceptor
                .replace_fast(TARGET1.unwrap(), NativePointer(detour1 as *mut c_void))
                .unwrap()
                .0,
        ));
        *ORIGINAL2.lock().unwrap().get_mut() = Some(transmute(
            interceptor
                .replace_fast(TARGET2.unwrap(), NativePointer(detour2 as *mut c_void))
                .unwrap()
                .0,
        ));
    }
    interceptor.end_transaction();
    *ENABLED.lock().unwrap().get_mut() = auto_enable;
    log::info!("ws2 socket dns hook installed");
}

pub fn remove() {
    let mut interceptor = Interceptor::obtain(&GUM);
    interceptor.begin_transaction();
    unsafe {
        interceptor.revert(TARGET1.unwrap());
    }
    interceptor.end_transaction();
}
