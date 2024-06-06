use std::{ffi::CStr, time::Duration};

use rumqttc::{Client, MqttOptions};
use serde::{Deserialize, Serialize};

mod hooks;
mod injector;

#[derive(Serialize, Deserialize)]
struct LogServerInfo {
    addr: Option<String>,
    port: Option<u16>,
}

struct MqttLogger {
    client: Client,
}

impl log::Log for MqttLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        todo!()
    }

    fn log(&self, record: &log::Record) {
        todo!()
    }

    fn flush(&self) {
        todo!()
    }
}

static mut LOGGER: Option<Box<dyn log::Log>> = None;

async unsafe fn run_with_logger_async(log_server_addr: Option<String>) {
    if let Some(log_server_addr) = log_server_addr {
        let mut mqttoptions = MqttOptions::new(libc::getpid().to_string(), log_server_addr, 1833);
        mqttoptions.set_keep_alive(Duration::from_secs(5));
        let (client, _) = Client::new(mqttoptions, 10);
        log::set_boxed_logger(Box::new(MqttLogger { client })).unwrap();
    }
    run_async().await
}

async unsafe fn run_async() {}

#[no_mangle]
unsafe extern "C" fn run() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async { run_async().await })
}

#[no_mangle]
unsafe extern "C" fn run_with_logger(log_server_addr: *const u8) {
    let log_server_addr = if log_server_addr.is_null() {
        None
    } else {
        Some(
            CStr::from_ptr(log_server_addr as *const i8)
                .to_str()
                .unwrap()
                .to_owned(),
        )
    };
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async move { run_with_logger_async(log_server_addr).await })
}

#[no_mangle]
unsafe extern "C" fn entrypoint(data: *const u8, stay_resident: *mut u32) {
    let log_server_info  =serde_json::from_slice<'a,LogServerInfo>(CStr::from_ptr(data as *const i8))
}
