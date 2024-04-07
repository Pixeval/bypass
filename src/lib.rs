use dll_syringe::payload_procedure;
use injector::Injection;
use windows::core::PCWSTR;

pub mod chrome_hook;
pub mod chrome_ssl_hook;
pub mod dns_hook;
pub mod injector;
pub mod schannel_ssl_hook;

payload_procedure! {
    fn install_dns_hook(auto_enable: bool) {
        dns_hook::install(auto_enable);

    }
}

payload_procedure! {
    fn install_ssl_hook(auto_enable: bool) {
        schannel_ssl_hook::install(auto_enable);
    }
}

payload_procedure! {
    fn install_chrome_hook(auto_enable: bool, injected_dll_path: String) {
        chrome_hook::install(auto_enable, injected_dll_path);

    }
}

payload_procedure! {
    fn install_chrome_ssl_hook(auto_enable: bool) {
        chrome_ssl_hook::install(auto_enable);
    }
}

payload_procedure! {
    fn remove_dns_hook() {
        dns_hook::remove();
    }
}

payload_procedure! {
    fn remove_ssl_hook() {
        schannel_ssl_hook::remove();
    }
}

payload_procedure! {
    fn remove_chrome_hook() {
        chrome_hook::remove();
    }
}

payload_procedure! {
    fn remove_chrome_ssl_hook() {
        chrome_ssl_hook::remove();
    }
}

payload_procedure! {
    fn set_dns_hook_enabled(enabled: bool) {
        *dns_hook::ENABLED.lock().unwrap().get_mut() = enabled;
    }
}
payload_procedure! {
    fn set_ssl_hook_enabled(enabled: bool) {
        *schannel_ssl_hook::ENABLED.lock().unwrap().get_mut() = enabled;
    }
}

payload_procedure! {
    fn set_chrome_hook_enabled(enabled: bool) {
        *chrome_hook::ENABLED.lock().unwrap().get_mut() = enabled;
    }
}

payload_procedure! {
    fn set_chrome_ssl_hook_enabled(enabled: bool) {
        *chrome_ssl_hook::ENABLED.lock().unwrap().get_mut() = enabled;
    }
}

#[no_mangle]
unsafe extern "C" fn injector_inject(
    pid: u32,
    payload_path: *const u16,
) -> *mut Injection<'static> {
    let injection =
        injector::inject(pid, PCWSTR::from_raw(payload_path).to_string().unwrap()).unwrap();
    return Box::leak(Box::new(injection)) as *mut Injection;
}

#[no_mangle]
unsafe extern "C" fn injector_eject(injection: *mut Injection) {
    injector::eject(injection.as_ref().unwrap()).unwrap()
}

#[no_mangle]
unsafe extern "C" fn injector_set_dns_hook_enabled(injection: *mut Injection, enabled: bool) {
    injector::set_dns_hook_enabled(injection.as_ref().unwrap(), enabled)
}

#[no_mangle]
unsafe extern "C" fn injector_set_ssl_hook_enabled(injection: *mut Injection, enabled: bool) {
    injector::set_ssl_hook_enabled(injection.as_ref().unwrap(), enabled)
}

#[no_mangle]
unsafe extern "C" fn injector_set_chrome_hook_enabled(injection: *mut Injection, enabled: bool) {
    injector::set_chrome_hook_enabled(injection.as_ref().unwrap(), enabled)
}

#[no_mangle]
unsafe extern "C" fn injector_set_chrome_ssl_hook_enabled(
    injection: *mut Injection,
    enabled: bool,
) {
    injector::set_chrome_ssl_hook_enabled(injection.as_ref().unwrap(), enabled)
}
