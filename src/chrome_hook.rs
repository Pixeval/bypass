use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};
use lazy_static::lazy_static;
use std::{cell::UnsafeCell, ffi::c_void, mem::transmute, sync::Mutex};
use windows::core::{PCWSTR, PWSTR};
use windows_sys::Win32::{
    Foundation::BOOL,
    Security::SECURITY_ATTRIBUTES,
    System::Threading::{PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW},
};

use crate::injector::{self};

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    pub static ref ENABLED: Mutex<UnsafeCell<bool>> = Mutex::new(UnsafeCell::new(false));
    static ref ORIGINAL: Mutex<UnsafeCell<Option<CreateProcessWFunc>>> =
        Mutex::new(UnsafeCell::new(None));
}

static mut INJECTED_DLL_PATH: Option<String> = None;
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
    let command_line = lpcommandline.to_string().unwrap();
    log::info!("{}", command_line);
    if command_line.contains("--utility-sub-type=network.mojom.NetworkService") {
        let pid = lpprocessinformation.as_ref().unwrap().dwProcessId;
        let path = INJECTED_DLL_PATH.as_ref().unwrap();
        let injection = injector::inject(pid, path).unwrap();
        injector::install_chrome_ssl_hook(&injection, true);
        injector::install_dns_hook(&injection, true);
    }
    return result;
}

pub fn install(auto_enable: bool, injected_dll_path: String) {
    eventlog::init("Pixeval.Bypass", log::Level::Trace).ok();
    let mut interceptr = Interceptor::obtain(&GUM);
    interceptr.begin_transaction();
    unsafe {
        TARGET = Module::find_export_by_name(Some("kernel32"), "CreateProcessW");
        *ORIGINAL.lock().unwrap().get_mut() = Some(transmute(
            interceptr
                .replace_fast(TARGET.unwrap(), NativePointer(detour as *mut c_void))
                .unwrap()
                .0,
        ));
    }
    interceptr.end_transaction();
    *ENABLED.lock().unwrap().get_mut() = auto_enable;
    unsafe { INJECTED_DLL_PATH = Some(injected_dll_path) };
    log::info!("chrome hook installed");
}

pub fn remove() {
    let mut interceptor = Interceptor::obtain(&GUM);
    interceptor.begin_transaction();
    unsafe {
        interceptor.revert(TARGET.unwrap());
    }
    interceptor.end_transaction();
}
