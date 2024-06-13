use std::{
    env::current_exe,
    fs,
    io::Error,
    path::{Path, PathBuf},
    process::Command,
};

#[tokio::test]
async fn firefox1() -> anyhow::Result<()> {
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
    anyhow::Ok(())
}
