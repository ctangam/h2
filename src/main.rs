use std::{net::ToSocketAddrs, str::FromStr, sync::Arc};

use bytes::BytesMut;
use color_eyre::eyre::eyre;
use h2::{DataFlags, Frame, FrameType, HeadersFlags, SettingsFlags};
use nom::Offset;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::rustls::{ClientConfig, KeyLogFile, RootCertStore};
use tracing::info;
use tracing_subscriber::{filter::targets::Targets, layer::SubscriberExt, util::SubscriberInitExt};

pub mod h2;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    real_main().await
}

async fn real_main() -> color_eyre::Result<()> {
    color_eyre::install().unwrap();

    let filter_layer =
        Targets::from_str(std::env::var("RUST_LOG").as_deref().unwrap_or("info")).unwrap();
    let format_layer = tracing_subscriber::fmt::layer();
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(format_layer)
        .init();

    info!("Setting up TLS");
    let mut root_store = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("msg") {
        root_store.add(cert)?;
    }

    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_config.key_log = Arc::new(KeyLogFile::new());
    client_config.alpn_protocols = vec![b"h2".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    info!("Performing DNS lookup");
    let addr = "example.org:443"
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| eyre!("Failed to resolve address for example.org:443"))?;

    info!("Establishing TCP connection...");
    let stream = TcpStream::connect(addr).await?;

    info!("Establishing TLS session...");
    let mut stream = connector.connect("example.org".try_into()?, stream).await?;

    info!("Establishing HTTP/2 connection...");

    info!("Writing preface");
    stream.write_all(h2::PREFACE).await?;

    let settings = Frame::new(FrameType::Settings(Default::default()), 0);
    info!("> {settings:?}");
    settings.write(&mut stream).await?;

    let mut encoder = hpack::Encoder::new();
    let headers: &[(&[u8], &[u8])] = &[
        (b":method", b"GET"),
        (b":path", b"/"),
        (b":scheme", b"https"),
        (b":authority", b"example.org"),
        (b"user-agent", b"fasterthanlime/http-crash-course"),
        // http://www.gnuterrypratchett.com/
        (b"x-clacks-overhead", b"GNU Terry Pratchett"),
    ];
    let mut headers_frame = Frame::new(
        FrameType::Headers(HeadersFlags::EndHeaders | HeadersFlags::EndStream),
        1,
    );
    headers_frame.payload.0 = encoder.encode(headers.iter().copied());
    info!("> {headers_frame:?}");
    headers_frame.write(&mut stream).await?;

    let mut decoder = hpack::Decoder::new();

    let mut buf: BytesMut = Default::default();
    loop {
        info!("Reading frame ({} bytes so far)", buf.len());
        if stream.read_buf(&mut buf).await? == 0 {
            info!("connection closed!");
            return Ok(());
        }

        let slice = &buf[..];
        let frame = match Frame::parse(slice) {
            Ok((rest, frame)) => {
                buf = buf.split_off(slice.offset(rest));
                frame
            }
            Err(e) => {
                if e.is_incomplete() {
                    // keep reading!
                    continue;
                }
                panic!("parse error: {e}");
            }
        };

        info!("< {frame:?}");
        match &frame.frame_type {
            FrameType::Settings(flags) => {
                if !flags.contains(SettingsFlags::Ack) {
                    info!("Acknowledging server settings");
                    let settings = Frame::new(FrameType::Settings(SettingsFlags::Ack.into()), 0);
                    info!("> {settings:?}");
                    settings.write(&mut stream).await?;
                }
            }
            FrameType::Headers(flags) => {
                assert!(
                    !flags.contains(HeadersFlags::Padded),
                    "padding not supported"
                );
                assert!(
                    !flags.contains(HeadersFlags::Priority),
                    "priority not supported"
                );
                assert!(
                    flags.contains(HeadersFlags::EndHeaders),
                    "continuation frames not supported"
                );

                let headers = decoder.decode(&frame.payload.0).unwrap();
                for (name, value) in headers {
                    info!(
                        "response header: {}: {}",
                        String::from_utf8_lossy(&name),
                        String::from_utf8_lossy(&value)
                    );
                }
            }
            FrameType::Data(flags) => {
                assert!(!flags.contains(DataFlags::Padded), "padding not supported");
                assert!(
                    flags.contains(DataFlags::EndStream),
                    "streaming response bodies not supported"
                );

                let response_body = String::from_utf8_lossy(&frame.payload.0);
                info!(
                    "response body: {}",
                    &response_body[..std::cmp::min(100, response_body.len())]
                );

                info!("All done!");
                return Ok(());
            }
            _ => {
                // ignore other types of frames
            }
        }
    }
}
