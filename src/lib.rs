use dll_syringe::payload_procedure;
use injector::Injection;
use windows::core::PCWSTR;

pub mod chrome_hook;
pub mod chrome_ssl_hook;
pub mod injector;
pub mod schannel_ssl_hook;
pub mod ws2_native_dns_hook;
pub mod ws2_socket_dns_hook;

payload_procedure! {
    fn install_ws2_native_dns_hook(auto_enable: bool) {
        ws2_native_dns_hook::install(auto_enable);
    }
}

payload_procedure! {
    fn install_ws2_socket_dns_hook(auto_enable: bool) {
        ws2_socket_dns_hook::install(auto_enable);
    }
}

payload_procedure! {
    fn install_schannel_ssl_hook(auto_enable: bool) {
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
    fn remove_ws2_native_dns_hook() {
        ws2_native_dns_hook::remove();
    }
}

payload_procedure! {
    fn remove_ws2_socket_dns_hook() {
        ws2_socket_dns_hook::remove();
    }
}

payload_procedure! {
    fn remove_schannel_ssl_hook() {
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
    fn set_ws2_native_dns_hook_enabled(enabled: bool) {
        *ws2_native_dns_hook::ENABLED.lock().unwrap().get_mut() = enabled;
    }
}

payload_procedure! {
    fn set_ws2_socket_dns_hook_enabled(enabled: bool) {
        *ws2_socket_dns_hook::ENABLED.lock().unwrap().get_mut() = enabled;
    }
}

payload_procedure! {
    fn set_schannel_ssl_hook_enabled(enabled: bool) {
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
unsafe extern "C" fn injector_install_ws2_native_dns_hook(
    injection: *mut Injection,
    auto_enable: bool,
) {
    injector::install_ws2_native_dns_hook(injection.as_ref().unwrap(), auto_enable)
}

#[no_mangle]
unsafe extern "C" fn injector_install_ws2_socket_dns_hook(
    injection: *mut Injection,
    auto_enable: bool,
) {
    injector::install_ws2_socket_dns_hook(injection.as_ref().unwrap(), auto_enable)
}

#[no_mangle]
unsafe extern "C" fn injector_install_schannel_ssl_hook(
    injection: *mut Injection,
    auto_enable: bool,
) {
    injector::install_schannel_ssl_hook(injection.as_ref().unwrap(), auto_enable)
}

#[no_mangle]
unsafe extern "C" fn injector_install_chrome_hook(
    injection: *mut Injection,
    auto_enable: bool,
    injected_dll_path: *const u16,
) {
    injector::install_chrome_hook(
        injection.as_ref().unwrap(),
        auto_enable,
        PCWSTR::from_raw(injected_dll_path).to_string().unwrap(),
    )
}

#[no_mangle]
unsafe extern "C" fn injector_install_chrome_ssl_hook(
    injection: *mut Injection,
    auto_enable: bool,
) {
    injector::install_chrome_ssl_hook(injection.as_ref().unwrap(), auto_enable)
}

#[no_mangle]
unsafe extern "C" fn injector_set_ws2_native_dns_hook_enabled(
    injection: *mut Injection,
    enabled: bool,
) {
    injector::set_ws2_native_dns_hook_enabled(injection.as_ref().unwrap(), enabled)
}

#[no_mangle]
unsafe extern "C" fn injector_set_ws2_socket_dns_hook_enabled(
    injection: *mut Injection,
    enabled: bool,
) {
    injector::set_ws2_socket_dns_hook_enabled(injection.as_ref().unwrap(), enabled)
}

#[no_mangle]
unsafe extern "C" fn injector_set_schannel_ssl_hook_enabled(
    injection: *mut Injection,
    enabled: bool,
) {
    injector::set_schannel_ssl_hook_enabled(injection.as_ref().unwrap(), enabled)
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
