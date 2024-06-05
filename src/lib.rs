use std::{ffi::CStr, time::Duration};

use rumqttc::{Client, MqttOptions};

mod hooks;
mod injector;

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

async unsafe fn run_async(log_server_addr: Option<String>, log_server_port: u16) {
    if let Some(log_server_addr) = log_server_addr {
        let mut mqttoptions =
            MqttOptions::new(libc::getpid().to_string(), log_server_addr, log_server_port);
        mqttoptions.set_keep_alive(Duration::from_secs(5));
        let (client, _) = Client::new(mqttoptions, 10);
        log::set_boxed_logger(Box::new(MqttLogger { client })).unwrap();
    }
}

#[no_mangle]
unsafe extern "C" fn run(log_server_host: *const u8, log_server_port: u16) {
    let log_server_host = if log_server_host.is_null() {
        None
    } else {
        Some(
            CStr::from_ptr(log_server_host as *const i8)
                .to_str()
                .unwrap()
                .to_owned(),
        )
    };
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async { run_async(log_server_host, log_server_port).await })
}
