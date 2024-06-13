mod boringssl_hook;
mod new_process_hook;
mod schannel_hook;
mod ws2_native_dns_hook;
mod ws2_socket_dns_hook;

pub async fn install_new_process_hook(
    #[cfg(feature = "log")] log_server_url: String,
) -> anyhow::Result<()> {
    new_process_hook::install().await?;
    anyhow::Ok(())
}

pub async fn install_all_hooks() -> anyhow::Result<()> {
    boringssl_hook::install().await?;
    schannel_hook::install().await?;
    ws2_native_dns_hook::install().await?;
    ws2_socket_dns_hook::install().await?;
    anyhow::Ok(())
}
