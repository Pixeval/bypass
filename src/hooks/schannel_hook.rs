use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};
use lazy_static::lazy_static;
use std::{cell::UnsafeCell, ffi::c_void, mem::transmute, ptr::null, sync::Mutex};
use windows::core::PCWSTR;
use windows_sys::{
    core::HRESULT,
    Win32::Security::{
        Authentication::Identity::{SecBufferDesc, ISC_REQ_FLAGS},
        Credentials::SecHandle,
    },
};

use super::HookError;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    static ref ORIGINAL: Mutex<UnsafeCell<Option<InitializeSecurityContextWFunc>>> =
        Mutex::new(UnsafeCell::new(None));
}

static mut TARGET: Option<NativePointer> = None;

type InitializeSecurityContextWFunc = unsafe extern "system" fn(
    phcredential: *const SecHandle,
    phcontext: *const SecHandle,
    psztargetname: PCWSTR,
    fcontextreq: ISC_REQ_FLAGS,
    reserved1: u32,
    targetdatarep: u32,
    pinput: *const SecBufferDesc,
    reserved2: u32,
    phnewcontext: *mut SecHandle,
    poutput: *mut SecBufferDesc,
    pfcontextattr: *mut u32,
    ptsexpiry: *mut i64,
) -> HRESULT;

unsafe extern "system" fn detour(
    phcredential: *const SecHandle,
    phcontext: *const SecHandle,
    psztargetname: PCWSTR,
    fcontextreq: ISC_REQ_FLAGS,
    reserved1: u32,
    targetdatarep: u32,
    pinput: *const SecBufferDesc,
    reserved2: u32,
    phnewcontext: *mut SecHandle,
    poutput: *mut SecBufferDesc,
    pfcontextattr: *mut u32,
    ptsexpiry: *mut i64,
) -> HRESULT {
    unsafe {
        let target_name = psztargetname.to_string().unwrap();
        if target_name.ends_with("pixiv.net") {
            let psztargetname = PCWSTR(null());
            return ORIGINAL.lock().unwrap().get_mut().unwrap()(
                phcredential,
                phcontext,
                psztargetname,
                fcontextreq,
                reserved1,
                targetdatarep,
                pinput,
                reserved2,
                phnewcontext,
                poutput,
                pfcontextattr,
                ptsexpiry,
            );
        }
    }
    return ORIGINAL.lock().unwrap().get_mut().unwrap()(
        phcredential,
        phcontext,
        psztargetname,
        fcontextreq,
        reserved1,
        targetdatarep,
        pinput,
        reserved2,
        phnewcontext,
        poutput,
        pfcontextattr,
        ptsexpiry,
    );
}

pub fn install() -> Result<(), HookError> {
    unsafe {
        let mut interceptr = Interceptor::obtain(&GUM);
        interceptr.begin_transaction();
        TARGET = Module::find_export_by_name(Some("sspicli"), "InitializeSecurityContextW")
            .ok_or(HookError::TargetNotFound)
            .map(Some)?;
        *ORIGINAL.lock().unwrap().get_mut() = Some(transmute(
            interceptr
                .replace_fast(TARGET.unwrap(), NativePointer(detour as *mut c_void))
                .unwrap()
                .0,
        ));
        interceptr.end_transaction();
        Ok(())
    }
}
