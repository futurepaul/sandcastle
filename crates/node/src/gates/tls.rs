//! The TLS client the node's outbound calls use (the bucket, the
//! credential source): the Mozilla roots, HTTP/1.1.

pub fn connector() -> tokio_rustls::TlsConnector {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
}
