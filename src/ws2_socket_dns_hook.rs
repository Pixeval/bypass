use frida_gum::interceptor::Interceptor;
use frida_gum::{Gum, Module, NativePointer};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::op::{Message, MessageType};
use hickory_resolver::proto::rr::rdata::A;
use hickory_resolver::proto::rr::Record;
use hickory_resolver::proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_resolver::Resolver;
use lazy_static::lazy_static;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::mem::transmute;
use std::sync::Mutex;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use windows_sys::Win32::Networking::WinSock::{WSASetEvent, LPWSAOVERLAPPED_COMPLETION_ROUTINE, SOCKADDR, SOCKET, WSABUF};
use windows_sys::Win32::System::IO::OVERLAPPED;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    static ref IO_LOOP: Runtime = Runtime::new().unwrap();
    pub static ref ENABLED: Mutex<UnsafeCell<bool>> = Mutex::new(UnsafeCell::new(false));
    static ref ORIGINAL1: Mutex<UnsafeCell<Option<WSASendToFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref ORIGINAL2: Mutex<UnsafeCell<Option<WSARecvFromFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref RESOLVER: Resolver =
        Resolver::new(ResolverConfig::google_https(), ResolverOpts::default()).unwrap();
}

struct Payload {
    message: Message,
    addr: SOCKADDR,
    addr_len: i32,
}
static mut TX: Option<UnboundedSender<Payload>> = None;
static mut RX: Option<UnboundedReceiver<Payload>> = None;
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
            let buffer = *lpbuffers.as_ref().unwrap();
            if let Ok(message) = Message::from_bytes(std::slice::from_raw_parts(
                buffer.buf,
                buffer.len as usize,
            )) {
                let addr = *lpto;
                if let Some(query) = message.query() {
                    let mut message = message.clone();
                    message.set_message_type(MessageType::Response);
                    if query.name().to_string().eq_ignore_ascii_case("pixiv.net.") {
                        message.add_answers([
                            Record::from_rdata(
                                query.name().clone(),
                                3000,
                                A::new(210, 140, 92, 181),
                            )
                            .into_record_of_rdata(),
                            Record::from_rdata(
                                query.name().clone(),
                                3000,
                                A::new(210, 140, 92, 183),
                            )
                            .into_record_of_rdata(),
                            Record::from_rdata(
                                query.name().clone(),
                                3000,
                                A::new(210, 140, 92, 187),
                            )
                            .into_record_of_rdata(),
                        ]);
                        TX.as_ref()
                            .unwrap()
                            .send(Payload {
                                message: message.to_owned(),
                                addr,
                                addr_len: itolen,
                            })
                            .ok();
                        let len = message.to_bytes().unwrap().len();
                        *lpnumberofbytessent = len as u32;
                        WSASetEvent((*lpoverlapped).hEvent);
                        return 0;
                    } else if query
                        .name()
                        .to_string()
                        .eq_ignore_ascii_case("www.pixiv.net.")
                    {
                        message.add_answers([
                            Record::from_rdata(
                                query.name().clone(),
                                3000,
                                A::new(104, 18, 42, 239),
                            )
                            .into_record_of_rdata(),
                            Record::from_rdata(
                                query.name().clone(),
                                3000,
                                A::new(172, 64, 145, 17),
                            )
                            .into_record_of_rdata(),
                        ]);
                        TX.as_ref()
                            .unwrap()
                            .send(Payload {
                                message: message.to_owned(),
                                addr,
                                addr_len: itolen,
                            })
                            .ok();
                        let len = message.to_bytes().unwrap().len();
                        *lpnumberofbytessent = len as u32;
                        WSASetEvent((*lpoverlapped).hEvent);
                        return 0;
                    }
                }
            }
        }
        log::info!("should be logged from send");
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
            let receiver = RX.as_mut().unwrap();
            if !receiver.is_empty() {
                let payload = receiver.blocking_recv().unwrap();
                let src = payload.message.to_bytes().unwrap();
                let buffer = *lpbuffers;
                let dest = std::slice::from_raw_parts_mut(buffer.buf, buffer.len as usize);
                dest[..src.len()].copy_from_slice(&src);
                *lpfrom = payload.addr;
                *lpfromlen = payload.addr_len;
                *lpnumberofbytesrecvd = src.len() as u32;
                WSASetEvent((*lpoverlapped).hEvent);
                return 0;
            }
        }
        log::info!("should be logged from recv");
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

pub fn install(auto_enable: bool) {
    eventlog::init("Pixeval.Bypass", log::Level::Trace).ok();
    let mut interceptor = Interceptor::obtain(&GUM);
    interceptor.begin_transaction();
    unsafe {
        TARGET1 = Module::find_export_by_name(Some("ws2_32"), "WSASendTo");
        TARGET2 = Module::find_export_by_name(Some("ws2_32"), "WSARecvFrom");
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
    let (tx, rx) = mpsc::unbounded_channel();
    unsafe {
        TX = Some(tx);
        RX = Some(rx);
    }
    log::info!("ws2 socket dns hook installed");
}

pub fn remove() {
    let mut interceptor = Interceptor::obtain(&GUM);
    interceptor.begin_transaction();
    unsafe {
        interceptor.revert(TARGET1.unwrap());
        interceptor.revert(TARGET2.unwrap());
    }
    interceptor.end_transaction();
}
