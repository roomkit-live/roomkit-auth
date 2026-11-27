//! The TLS every request of the crate is made over.

/// TLS with rustls's ring provider and the webpki roots: the same trust on
/// every host, and no system TLS library. HTTP/1.1 is offered by ALPN, as
/// reqwest's own rustls configuration does.
pub(crate) fn tls_config() -> Option<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .ok()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Some(config)
}
