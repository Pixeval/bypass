use std::{
    env::current_exe,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use windows_registry::LOCAL_MACHINE;

#[tokio::test]
async fn chrome1() -> anyhow::Result<()> {
    let smi = LOCAL_MACHINE.open("SOFTWARE\\Clients\\StartMenuInternet")?;
    let chrome_key = smi
        .keys()?
        .filter_map(|k| smi.open(k).ok())
        .find(|k| k.get_string("").map_or(false, |v| v.eq("Google Chrome")))
        .expect("Please install google chrome first!");
    let chrome_path = chrome_key
        .open("shell\\open\\command")
        .unwrap()
        .get_string("")
        .unwrap();
    unsafe {
        let bypass_path = test_cdylib::build_current_project();
        bypass::inject_and_run(
            libc::getpid() as u32,
            Some(bypass_path.as_path().to_str().unwrap().to_owned()),
        );
    }
    let mut chrome_process = Command::new(chrome_path.trim_matches('"'))
        .arg("--no-proxy-server")
        .spawn()
        .expect("Failed to start Chrome.");
    anyhow::Ok(())
}
