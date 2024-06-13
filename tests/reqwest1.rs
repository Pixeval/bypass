use std::ffi::CString;

use anyhow::Ok;
use log::info;
use reqwest::{ClientBuilder, StatusCode};

#[test_log::test(tokio::test)]
async fn reqwest1() -> anyhow::Result<()> {
    let logger_url = bypass::log::setup_log_server_async().await?;
    info!("{}",logger_url);
    unsafe {
        let bypass_path = test_cdylib::build_current_project();
        info!("{:?}", bypass_path);
        let bypass_lib = libloading::Library::new(bypass_path)?;
        info!("{:?}", bypass_lib);
        let bypass_run: libloading::Symbol<unsafe extern "C" fn(*const u8)> =
            bypass_lib.get(b"run_with_log_server")?;
        info!("{:?}", bypass_run);
        bypass_run(CString::new(logger_url).unwrap().into_raw() as *const u8);
    }

    let client = ClientBuilder::new().no_proxy().build()?;

    let url = "https://www.pixiv.net/artworks/117400067";

    let response = client.get(url).send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    anyhow::Ok(())
}
