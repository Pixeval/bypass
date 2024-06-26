use std::ffi::{CStr, CString};

use hooks::HookError;
use injector::InjectorError;
use libc::getpid;

mod hooks;
mod injector;

#[macro_use]
extern crate log;

#[no_mangle]
pub unsafe extern "C" fn run() {
    eventlog::init("pixevy", log::Level::Info).ok();
    info!("bypass running on process: {}", getpid());
    hooks::install_all_hooks()
        .map_err(|e| error!("{:?}", e))
        .ok();
}

/// stupid libloading
pub unsafe fn inject_and_run(pid: u32, payload_path: Option<String>) -> Result<(), InjectorError> {
    let mut injection = injector::inject(pid, payload_path)?;
    injection
        .get_func::<unsafe extern "C" fn()>("run")
        .unwrap()
        .unwrap()
        .call()
        .inspect_err(|e| error!("{:?}", e));
    Ok(())
}
