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
use windows_sys::Win32::Networking::WinSock::{ADDRINFOA, AF_INET, SOCKADDR, SOCKADDR_IN};

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    pub static ref ENABLED: Mutex<UnsafeCell<bool>> = Mutex::new(UnsafeCell::new(false));
    static ref ORIGINAL1: Mutex<UnsafeCell<Option<GetAddrInfoAFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref RESOLVER: Resolver =
        Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();
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
    pnodename: PCSTR,
    pservicename: PCSTR,
    phints: *const ADDRINFOA,
    ppresult: *mut *mut ADDRINFOA,
) -> i32 {
    let result =
        ORIGINAL1.lock().unwrap().get_mut().unwrap()(pnodename, pservicename, phints, ppresult);
    unsafe {
        if *ENABLED.lock().unwrap().get_mut() {
            let name = CStr::from_ptr(pnodename as *const c_char).to_str().unwrap();
            (*(**ppresult).ai_addr) = transmute(lookup(name));
            return 0;
        }
    }

    return result;
}

pub fn install(auto_enable: bool) {
    eventlog::init("Pixeval.Bypass", log::Level::Trace).ok();
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
