use frida_gum::Gum;
use thiserror::Error;

mod boringssl_hook;
mod new_process_hook;
mod schannel_hook;
mod ws2_native_dns_hook;
mod ws2_socket_dns_hook;

#[derive(Error, Debug)]
pub enum HookError {
    #[error("target function to install hook could not be found")]
    TargetNotFound,
    #[error("module to install hook could not be found")]
    ModuleNotFound(),
    #[error("failed to install hook")]
    InstallHookFailed(),
}

pub fn install_all_hooks() -> Result<(), HookError> {
    new_process_hook::install();
    schannel_hook::install();
    ws2_native_dns_hook::install();
    ws2_socket_dns_hook::install();
    boringssl_hook::install();
    Ok(())
}
