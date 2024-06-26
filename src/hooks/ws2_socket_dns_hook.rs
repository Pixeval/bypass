use flume::{Receiver, Sender};
use frida_gum::interceptor::Interceptor;
use frida_gum::{Gum, Module, NativePointer};
use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use lazy_static::lazy_static;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::mem::transmute;
use std::sync::Mutex;
use windows_sys::Win32::Networking::WinSock::{
    WSASetEvent, LPWSAOVERLAPPED_COMPLETION_ROUTINE, SOCKADDR, SOCKET, WSABUF,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

use super::HookError;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    static ref ORIGINAL1: Mutex<UnsafeCell<Option<WSASendToFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref ORIGINAL2: Mutex<UnsafeCell<Option<WSARecvFromFunc>>> =
        Mutex::new(UnsafeCell::new(None));
}

struct Payload {
    message: Message,
    addr: SOCKADDR,
    addr_len: i32,
}
static mut TX: Option<Sender<Payload>> = None;
static mut RX: Option<Receiver<Payload>> = None;
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
        let buffer = *lpbuffers.as_ref().unwrap();
        if let Ok(message) =
            Message::from_bytes(std::slice::from_raw_parts(buffer.buf, buffer.len as usize))
        {
            let addr = *lpto;
            if let Some(query) = message.query() {
                let mut message = message.clone();
                message.set_message_type(MessageType::Response);
                let mut header = message.header().clone();
                header.set_answer_count(1);
                message.set_header(header);
                if query.name().to_string().ends_with("pixiv.net.") {
                    message.add_answers([Record::from_rdata(
                        query.name().clone(),
                        1000,
                        A::new(210, 140, 92, 183),
                    )
                    .into_record_of_rdata()]);
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
                } else if query.name().to_string().ends_with("pximg.net.") {
                    message.add_answers([Record::from_rdata(
                        query.name().clone(),
                        1000,
                        A::new(210, 140, 139, 131),
                    )
                    .into_record_of_rdata()]);
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
        let receiver = RX.as_mut().unwrap();
        if !receiver.is_empty() {
            let payload = receiver.recv().unwrap();
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

pub fn install() -> Result<(), HookError> {
    unsafe {
        let mut interceptor = Interceptor::obtain(&GUM);
        interceptor.begin_transaction();
        TARGET1 = Module::find_export_by_name(Some("ws2_32"), "WSASendTo")
            .ok_or(HookError::TargetNotFound)
            .map(Some)?;
        TARGET2 = Module::find_export_by_name(Some("ws2_32"), "WSARecvFrom")
            .ok_or(HookError::TargetNotFound)
            .map(Some)?;
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
        interceptor.end_transaction();
        let (tx, rx) = flume::unbounded();
        TX = Some(tx);
        RX = Some(rx);
        Ok(())
    }
}
