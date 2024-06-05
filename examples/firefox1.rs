use bypass::injector;
use std::{
    env::current_exe,
    fs,
    io::Error,
    path::{Path, PathBuf},
    process::Command,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let chrome_paths =
        which::which_in_global("firefox.exe", Some(r"C:\Users\Summpot\Desktop\chrome-win"))
            .expect("You should install chrome first.");

    let mut chrome_process = Command::new(chrome_paths.into_iter().next().unwrap())
        .arg("--no-proxy-server")
        .spawn()
        .expect("Failed to start Chrome.");

    let path: PathBuf = current_exe()?
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("bypass.dll");
    let path = fs::canonicalize(path)?;
    let injection = injector::inject(chrome_process.id(), &path)?;
    injector::install_chrome_hook(&injection, true, path.to_str().unwrap().to_string());
    chrome_process.wait()?;
    Ok(())
}
