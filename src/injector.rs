use std::path::Path;

use dll_syringe::error::{EjectError, InjectError};
use dll_syringe::process::{BorrowedProcess, OwnedProcess, ProcessModule};
use dll_syringe::Syringe;

pub struct Injection<'a> {
    syringe_ptr: *mut Syringe,
    pub module: ProcessModule<BorrowedProcess<'a>>,
}

impl Injection<'static> {
    pub fn eject(&self) -> Result<(), EjectError> {
        eject(self)
    }
}

pub fn inject(pid: u32, payload_path: impl AsRef<Path>) -> Result<Injection<'static>, InjectError> {
    let process = OwnedProcess::from_pid(pid).unwrap();
    let syringe = Box::new(Syringe::for_process(process));
    let syringe_ptr = Box::leak(syringe) as *mut Syringe;
    unsafe {
        syringe_ptr
            .as_ref()
            .unwrap()
            .inject(payload_path)
            .map(|module| Injection {
                syringe_ptr,
                module,
            })
    }
}

pub fn eject(injection: &Injection) -> Result<(), EjectError> {
    unsafe {
        injection
            .syringe_ptr
            .as_ref()
            .unwrap()
            .eject(injection.module)
    }
}

pub fn install_ws2_native_dns_hook(injection: &Injection, enabled: bool) {
    let remote = unsafe {
        injection
            .syringe_ptr
            .as_ref()
            .unwrap()
            .get_payload_procedure::<fn(bool) -> ()>(injection.module, "install_ws2_native_dns_hook")
    }
    .unwrap()
    .unwrap();
    remote.call(&enabled).unwrap();
}

pub fn install_ws2_socket_dns_hook(injection: &Injection, enabled: bool) {
    let remote = unsafe {
        injection
            .syringe_ptr
            .as_ref()
            .unwrap()
            .get_payload_procedure::<fn(bool) -> ()>(injection.module, "install_ws2_socket_dns_hook")
    }
    .unwrap()
    .unwrap();
    remote.call(&enabled).unwrap();
}

pub fn install_schannel_ssl_hook(injection: &Injection, enabled: bool) {
    let remote = unsafe {
        injection
            .syringe_ptr
            .as_ref()
            .unwrap()
            .get_payload_procedure::<fn(bool) -> ()>(injection.module, "install_schannel_ssl_hook")
    }
    .unwrap()
    .unwrap();
    remote.call(&enabled).unwrap();
}

pub fn install_chrome_hook(injection: &Injection, enabled: bool, injected_dll_path: String) {
    let remote = unsafe {
        injection
            .syringe_ptr
            .as_ref()
            .unwrap()
            .get_payload_procedure::<fn(bool, String) -> ()>(
                injection.module,
                "install_chrome_hook",
            )
    }
    .unwrap()
    .unwrap();
    remote.call(&enabled, &injected_dll_path).unwrap();
}

pub fn install_chrome_ssl_hook(injection: &Injection, enabled: bool) {
    let remote = unsafe {
        injection
            .syringe_ptr
            .as_ref()
            .unwrap()
            .get_payload_procedure::<fn(bool) -> ()>(injection.module, "install_chrome_ssl_hook")
    }
    .unwrap()
    .unwrap();
    remote.call(&enabled).unwrap();
}

pub fn set_ws2_native_dns_hook_enabled(injection: &Injection, enabled: bool) {
    let remote = unsafe {
        injection
            .syringe_ptr
            .as_ref()
            .unwrap()
            .get_payload_procedure::<fn(bool) -> ()>(
                injection.module,
                "set_ws2_native_dns_hook_enabled",
            )
    }
    .unwrap()
    .unwrap();
    remote.call(&enabled).unwrap();
}

pub fn set_ws2_socket_dns_hook_enabled(injection: &Injection, enabled: bool) {
    let remote = unsafe {
        injection
            .syringe_ptr
            .as_ref()
            .unwrap()
            .get_payload_procedure::<fn(bool) -> ()>(
                injection.module,
                "set_ws2_socket_dns_hook_enabled",
            )
    }
    .unwrap()
    .unwrap();
    remote.call(&enabled).unwrap();
}

pub fn set_schannel_ssl_hook_enabled(injection: &Injection, enabled: bool) {
    let remote = unsafe {
        injection
            .syringe_ptr
            .as_ref()
            .unwrap()
            .get_payload_procedure::<fn(bool) -> ()>(injection.module, "set_schannel_ssl_hook_enabled")
    }
    .unwrap()
    .unwrap();
    remote.call(&enabled).unwrap();
}

pub fn set_chrome_hook_enabled(injection: &Injection, enabled: bool) {
    let remote = unsafe {
        injection
            .syringe_ptr
            .as_ref()
            .unwrap()
            .get_payload_procedure::<fn(bool) -> ()>(injection.module, "set_chrome_hook_enabled")
    }
    .unwrap()
    .unwrap();
    remote.call(&enabled).unwrap();
}

pub fn set_chrome_ssl_hook_enabled(injection: &Injection, enabled: bool) {
    let remote = unsafe {
        injection
            .syringe_ptr
            .as_ref()
            .unwrap()
            .get_payload_procedure::<fn(bool) -> ()>(injection.module, "set_chrome_ssl_hook_enabled")
    }
    .unwrap()
    .unwrap();
    remote.call(&enabled).unwrap();
}
