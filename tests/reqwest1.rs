use reqwest::{ClientBuilder, Error, StatusCode};

#[tokio::test]
async fn reqwest1() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let bypass_path = test_cdylib::build_current_project();
        let bypass = libloading::Library::new(bypass_path)?;
        let bypass_run: libloading::Symbol<unsafe extern "C" fn()> = bypass.get(b"run")?;
        bypass_run();
    }
    let client = ClientBuilder::new().no_proxy().build()?;

    let url = "https://www.pixiv.net/artworks/117400067";

    let response = client.get(url).send().await?;

    println!("{}", response.status());
    Ok(())
}
