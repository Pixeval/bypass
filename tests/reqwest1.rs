use std::ffi::CString;

use log::info;
use reqwest::{ClientBuilder, StatusCode};

#[tokio::test]
async fn reqwest1() -> anyhow::Result<()> {
    let bypass_path = test_cdylib::build_current_project();
    unsafe {
        bypass::inject_and_run(
            libc::getpid() as u32,
            Some(bypass_path.to_str().unwrap().to_owned()),
        );
    }
    let client = ClientBuilder::new().no_proxy().build()?;

    let url = "https://www.pixiv.net/artworks/117400067";

    let response = client.get(url).send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    anyhow::Ok(())
}
