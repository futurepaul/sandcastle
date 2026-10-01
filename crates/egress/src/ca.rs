//! The interception CA: made on the node, its key never leaving the node
//! side (the VM process's jail has no copy), its certificate handed to the
//! guest where Cloudflare's containers find theirs. Leaf certificates are
//! minted per intercepted name and kept, a bounded number.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use thiserror::Error;

/// Leaf configurations kept at once; past it the cache starts over.
pub const LEAVES_MAX: usize = 256;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("minting a certificate: {0}")]
    Mint(#[from] rcgen::Error),
    #[error("a TLS configuration: {0}")]
    Tls(#[from] rustls::Error),
}

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    cert_der: CertificateDer<'static>,
    cert_pem: String,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl Ca {
    pub fn generate(common_name: &str) -> Result<Ca, CaError> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok(Ca {
            cert_pem: cert.pem(),
            cert_der: cert.der().clone(),
            issuer: Issuer::new(params, key),
            leaves: Mutex::new(HashMap::new()),
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// The TLS configuration that presents `host` to the guest.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        if let Some(c) = self.leaves.lock().expect("never poisoned").get(host) {
            return Ok(c.clone());
        }
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        let key = KeyPair::generate()?;
        let leaf = params.signed_by(&key, &self.issuer)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone(), self.cert_der.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )?;
        // The proxy speaks HTTP/1.1 to the guest; a client offering h2
        // falls back to it.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        let mut leaves = self.leaves.lock().expect("never poisoned");
        if leaves.len() >= LEAVES_MAX {
            leaves.clear();
        }
        leaves.insert(host.to_string(), config.clone());
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;

    // Goal: a leaf the CA mints verifies against the CA alone.
    #[test]
    fn leaf_chains_to_the_ca() {
        let ca = Ca::generate("sandcastle test CA").unwrap();
        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        let a = ca.server_config("model.example.com").unwrap();
        let b = ca.server_config("model.example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b), "cached");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build().unwrap();
        let leaf = {
            let mut params = CertificateParams::new(vec!["x.example".to_string()]).unwrap();
            params.distinguished_name.push(DnType::CommonName, "x.example");
            let key = KeyPair::generate().unwrap();
            params.signed_by(&key, &ca.issuer).unwrap()
        };
        let name = rustls_pki_types::ServerName::try_from("x.example").unwrap();
        verifier
            .verify_server_cert(leaf.der(), &[], &name, &[], rustls_pki_types::UnixTime::now())
            .unwrap();
        let wrong = rustls_pki_types::ServerName::try_from("y.example").unwrap();
        assert!(verifier.verify_server_cert(leaf.der(), &[], &wrong, &[], rustls_pki_types::UnixTime::now()).is_err());
    }
}
