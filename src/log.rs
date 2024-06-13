use std::net::{Ipv4Addr, SocketAddrV4, ToSocketAddrs};

use axum::{routing::post, Json, Router};
use log::Level;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

struct Logger {
    logger_url: String,
    runtime_handle: Handle,
    client: Client,
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let client = self.client.clone();
        let log_server_url = self.logger_url.clone();
        let message = LogMessage {
            message: format!("{}", record.args()),
            level: record.level(),
        };
        self.runtime_handle.spawn(async move {
            client
                .post(log_server_url)
                .json(&message)
                .send()
                .await
                .unwrap();
        });
    }

    fn flush(&self) {}
}

pub fn set_remote_logger(
    logger_url: &str,
    runtime_handle: tokio::runtime::Handle,
) -> anyhow::Result<()> {
    let logger = Box::new(Logger {
        logger_url: String::from(logger_url),
        runtime_handle,
        client: reqwest::Client::new(),
    });
    log::set_boxed_logger(logger)?;
    anyhow::Ok(())
}

pub async fn setup_log_server_async() -> anyhow::Result<String> {
    let app = Router::new().route("/log", post(log));
    let listener = tokio::net::TcpListener::bind("localhost:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async {
        axum::serve(listener, app).await.unwrap();
    });
    anyhow::Ok(format!("http://localhost:{}{}", addr.port(), "/log"))
}

#[derive(Clone, Serialize, Deserialize)]
struct LogMessage {
    message: String,
    level: Level,
}

async fn log(Json(payload): Json<LogMessage>) -> axum::http::StatusCode {
    info!("receive log");
    let level = payload.level;
    let message = payload.message;
    match level {
        Level::Error => error!("{}", message),
        Level::Warn => warn!("{}", message),
        Level::Info => info!("{}", message),
        Level::Debug => debug!("{}", message),
        Level::Trace => trace!("{}", message),
    }
    axum::http::StatusCode::OK
}
