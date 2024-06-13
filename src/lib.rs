use std::ffi::{CStr, CString};

mod hooks;
mod injector;
#[cfg(feature = "log")]
pub mod log;

#[macro_use]
extern crate log as external_log;

#[no_mangle]
#[cfg(feature = "log")]
unsafe extern "C" fn setup_log_server() -> *const u8 {
    let logger_url = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move { log::setup_log_server_async().await.unwrap() });
    CString::new(logger_url).unwrap().into_raw() as *const u8
}

#[no_mangle]
unsafe extern "C" fn run() {
    info!("enter bypass");
    #[cfg(feature = "log")]
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            #[cfg(feature = "log")]
            let logger_url = log::setup_log_server_async().await.unwrap();
            hooks::install_new_process_hook(
                #[cfg(feature = "log")]
                logger_url,
            )
            .await
            .unwrap();
            hooks::install_all_hooks().await.unwrap();
        });
}

#[no_mangle]
#[cfg(feature = "log")]
unsafe extern "C" fn run_with_log_server(logger_url: *const u8) {
    println!("111");
    if !logger_url.is_null() {
        if let Ok(logger_url) = CStr::from_ptr(logger_url as *const i8).to_str() {
            println!("222");
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    println!("333");
                    log::set_remote_logger(logger_url, tokio::runtime::Handle::current()).unwrap();
                    println!("444");
                    info!("Successfully connected to logger:{}", logger_url);
                    println!("555");
                    hooks::install_all_hooks();
                    println!("666");
                });
        }
    }
}
