use bypass::injector;
use std::{
    env::current_exe,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[tokio::main]
async fn main() {
    let chrome_paths = which::which_in_global(
        "chrome.exe",
        Some(r"C:\Users\Summpot\Desktop\chrome-win"),
    )
    .expect("You should install chrome first.");

    let mut chrome_process = Command::new(chrome_paths.into_iter().next().unwrap())
        .arg("--no-proxy-server")
        .spawn()
        .expect("Failed to start Chrome.");

    let path: PathBuf = current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("bypass.dll");
    let path = fs::canonicalize(path).unwrap();
    let _exists = Path::exists(&path);
    let injection = injector::inject(chrome_process.id(), &path).unwrap();
    injector::install_chrome_hook(&injection, true, path.to_str().unwrap().to_string());
    chrome_process.wait().unwrap();
}
