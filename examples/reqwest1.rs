use bypass::{schannel_ssl_hook, ws2_native_dns_hook, ws2_socket_dns_hook};
use reqwest::{ClientBuilder, Error, StatusCode};

#[tokio::main]
async fn main() -> Result<(), Error> {
    schannel_ssl_hook::install(true);
    ws2_native_dns_hook::install(true);
    let client = ClientBuilder::new().no_proxy().build().unwrap();

    let url = "https://www.pixiv.net/artworks/117400067";

    let response = client.get(url).send().await?;

    println!("{}", response.status());
    // ws2_native_dns_hook::remove();
    schannel_ssl_hook::remove();
    ws2_native_dns_hook::remove();
    Ok(())
}
