use anyhow::Ok;
use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};
use lazy_static::lazy_static;
use std::{cell::UnsafeCell, ffi::c_void, mem::transmute, sync::Mutex};
use windows::core::{PCWSTR, PWSTR};
use windows_sys::Win32::{
    Foundation::BOOL,
    Security::SECURITY_ATTRIBUTES,
    System::Threading::{PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW},
};

use crate::injector;

lazy_static! {
    static ref ORIGINAL: Mutex<UnsafeCell<Option<CreateProcessWFunc>>> =
        Mutex::new(UnsafeCell::new(None));
}

static mut TARGET: Option<NativePointer> = None;

type CreateProcessWFunc = unsafe extern "system" fn(
    lpapplicationname: PCWSTR,
    lpcommandline: PWSTR,
    lpprocessattributes: *const SECURITY_ATTRIBUTES,
    lpthreadattributes: *const SECURITY_ATTRIBUTES,
    binherithandles: BOOL,
    dwcreationflags: PROCESS_CREATION_FLAGS,
    lpenvironment: *const c_void,
    lpcurrentdirectory: PCWSTR,
    lpstartupinfo: *const STARTUPINFOW,
    lpprocessinformation: *mut PROCESS_INFORMATION,
) -> BOOL;

unsafe extern "system" fn detour(
    lpapplicationname: PCWSTR,
    lpcommandline: PWSTR,
    lpprocessattributes: *const SECURITY_ATTRIBUTES,
    lpthreadattributes: *const SECURITY_ATTRIBUTES,
    binherithandles: BOOL,
    dwcreationflags: PROCESS_CREATION_FLAGS,
    lpenvironment: *const c_void,
    lpcurrentdirectory: PCWSTR,
    lpstartupinfo: *const STARTUPINFOW,
    lpprocessinformation: *mut PROCESS_INFORMATION,
) -> BOOL {
    let result = ORIGINAL.lock().unwrap().get_mut().unwrap()(
        lpapplicationname,
        lpcommandline,
        lpprocessattributes,
        lpthreadattributes,
        binherithandles,
        dwcreationflags,
        lpenvironment,
        lpcurrentdirectory,
        lpstartupinfo,
        lpprocessinformation,
    );
    let injection = injector::inject(lpprocessinformation.as_ref().unwrap().dwProcessId).unwrap();
    result
}

pub async fn install() -> anyhow::Result<()> {
    unsafe {
        let gum = Gum::obtain();
        let mut interceptr = Interceptor::obtain(&gum);
        interceptr.begin_transaction();
        TARGET = Module::find_export_by_name(Some("kernel32"), "CreateProcessW");
        *ORIGINAL.lock().unwrap().get_mut() = Some(transmute(
            interceptr
                .replace_fast(TARGET.unwrap(), NativePointer(detour as *mut c_void))
                .unwrap()
                .0,
        ));
        interceptr.end_transaction();
    }
    anyhow::Ok(())
}
