mod new_process_hook;
mod boringssl_hook;
mod schannel_ssl_hook;
mod ws2_native_dns_hook;
mod ws2_socket_dns_hook;

pub fn install_all_hooks() {
    new_process_hook::install();
    boringssl_hook::install();
    schannel_ssl_hook::install();
    ws2_native_dns_hook::install();
    ws2_socket_dns_hook::install();
}
