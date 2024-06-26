use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};
use lazy_static::lazy_static;
use std::{cell::UnsafeCell, ffi::c_void, mem::transmute, sync::Mutex};
use windows::core::{PCWSTR, PWSTR};
use windows_sys::Win32::{
    Foundation::BOOL,
    Security::SECURITY_ATTRIBUTES,
    System::Threading::{PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW},
};

use crate::{inject_and_run, injector};

use super::HookError;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
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
    if result != 0 {
        //ensure process successfully created
        inject_and_run(lpprocessinformation.as_ref().unwrap().dwProcessId, None).ok();
    }
    result
}

pub fn install() -> Result<(), HookError> {
    unsafe {
        let mut interceptr = Interceptor::obtain(&GUM);
        interceptr.begin_transaction();
        TARGET = Module::find_export_by_name(Some("kernel32"), "CreateProcessW")
            .ok_or(HookError::TargetNotFound)
            .map(Some)?;
        *ORIGINAL.lock().unwrap().get_mut() = Some(transmute(
            interceptr
                .replace_fast(TARGET.unwrap(), NativePointer(detour as *mut c_void))
                .unwrap()
                .0,
        ));
        interceptr.end_transaction();
        info!("new process hook installed");
        Ok(())
    }
}
