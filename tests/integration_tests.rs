use bypass::{dns_hook, injector, schannel_ssl_hook};
use reqwest::{Client, StatusCode};

#[futures_test::test]
async fn reqwest_test1() {
    dns_hook::install(true);
    schannel_ssl_hook::install(true);

    let client = Client::new();

    let url = "https://www.pixiv.net/artworks/117400067";

    let response = client.get(url).send().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    dns_hook::remove();
    schannel_ssl_hook::remove();
}

use std::{
    env::current_exe,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[futures_test::test]
async fn chrome_test1() {
    let chrome_paths = which::which_in_global(
        "msedge.exe",
        Some(r"C:\Program Files (x86)\Microsoft\Edge\Application"),
    )
    .expect("You should install chrome first.");
    let mut chrome_process = Command::new(chrome_paths.take(1).next().unwrap())
        .arg("--no-proxy-server")
        .spawn()
        .expect("Failed to start Chrome.");
    let path: PathBuf = current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("..")
        .join("bypass.dll");
    let path = fs::canonicalize(path).unwrap();
    let _exists = Path::exists(&path);
    let injection = injector::inject(chrome_process.id(), &path).unwrap();
    injector::install_chrome_hook(&injection, true, path.to_str().unwrap().to_string());
    chrome_process.wait().unwrap();
}
