//! A registry client over hyper and rustls (the distribution spec's pull
//! side): anonymous bearer tokens, manifests (an index resolved to one
//! platform), and blobs streamed to the store with their size and digest
//! checked as they arrive. Redirects are followed a bounded number of
//! times, and a token is never sent to a host other than the registry's.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::digest::{check_file, Digest, DigestError, Hasher};
use crate::manifest::{self, Descriptor, ImageConfig, Manifest, ManifestError, INDEX_TYPES, MANIFEST_TYPES};
use crate::reference::Reference;
use crate::{DOCUMENT_BYTES_MAX, REDIRECTS_MAX};

const USER_AGENT: &str = "sandcastle-rootfs/0.1";
/// A token answer, as read.
const TOKEN_BYTES_MAX: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("{url}: {message}")]
    Http { url: String, message: String },
    #[error("{url} answered {status}")]
    Status { url: String, status: u16 },
    #[error("{0}")]
    Auth(String),
    #[error(transparent)]
    Digest(#[from] DigestError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("{what}: {source}")]
    Io { what: &'static str, source: std::io::Error },
    #[error("{0} passes its limit")]
    TooLarge(&'static str),
}

fn http(url: &Url, e: impl std::fmt::Display) -> RegistryError {
    RegistryError::Http { url: url.to_string(), message: e.to_string() }
}

/// A `WWW-Authenticate: Bearer` challenge.
#[derive(Debug, PartialEq, Eq)]
pub struct Challenge {
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

/// Parses `Bearer realm="…",service="…",scope="…"`.
pub fn parse_challenge(h: &str) -> Option<Challenge> {
    let rest = h.strip_prefix("Bearer ")?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    // Bounded by the header's length: each pass consumes one key="value".
    let mut s = rest.trim();
    while !s.is_empty() {
        let (key, after) = s.split_once('=')?;
        let after = after.strip_prefix('"')?;
        let end = after.find('"')?;
        let value = after[..end].to_string();
        match key.trim() {
            "realm" => realm = Some(value),
            "service" => service = Some(value),
            "scope" => scope = Some(value),
            _ => {}
        }
        s = after[end + 1..].trim_start_matches(',').trim();
    }
    let realm = realm?;
    if !realm.starts_with("https://") {
        return None;
    }
    Some(Challenge { realm, service, scope })
}

pub struct Registry {
    tls: tokio_rustls::TlsConnector,
    token: Option<(String, String)>,
}

impl Default for Registry {
    fn default() -> Self {
        Registry::new()
    }
}

/// An image's manifest and config, resolved for one platform.
pub struct Pulled {
    pub manifest_digest: Digest,
    pub manifest: Manifest,
    pub config: ImageConfig,
}

impl Registry {
    pub fn new() -> Registry {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports the default versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Registry { tls: tokio_rustls::TlsConnector::from(Arc::new(config)), token: None }
    }

    async fn get(&self, url: &Url, accept: &str, bearer: Option<&str>) -> Result<Response<Incoming>, RegistryError> {
        if url.scheme() != "https" {
            return Err(http(url, "not https"));
        }
        let host = url.host_str().ok_or_else(|| http(url, "no host"))?.to_string();
        let port = url.port().unwrap_or(443);
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.map_err(|e| http(url, e))?;
        let name = rustls_pki_types::ServerName::try_from(host.clone()).map_err(|e| http(url, e))?;
        let tls = self.tls.connect(name, tcp).await.map_err(|e| http(url, e))?;
        let (mut send, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.map_err(|e| http(url, e))?;
        tokio::spawn(conn);
        let path = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_string(),
        };
        let mut req = Request::get(path).header("host", &host).header("user-agent", USER_AGENT).header("accept", accept);
        if let Some(t) = bearer {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let req = req.body(Empty::<Bytes>::new()).map_err(|e| http(url, e))?;
        send.send_request(req).await.map_err(|e| http(url, e))
    }

    /// GETs `url`, with the registry's token if it has one for `repo`,
    /// fetching one on a 401, and following redirects (without the token
    /// once the host changes).
    async fn fetch(&mut self, r: &Reference, url: Url, accept: &str) -> Result<Response<Incoming>, RegistryError> {
        let mut url = url;
        let registry_host = url.host_str().map(str::to_string);
        let mut retried_auth = false;
        // Bounded: REDIRECTS_MAX redirects and one retry with a token.
        for _ in 0..=REDIRECTS_MAX + 1 {
            let same_host = url.host_str().map(str::to_string) == registry_host;
            let token = self.token.as_ref().filter(|(repo, _)| same_host && *repo == r.repository).map(|(_, t)| t.clone());
            let resp = self.get(&url, accept, token.as_deref()).await?;
            let status = resp.status().as_u16();
            match status {
                200 => return Ok(resp),
                301 | 302 | 303 | 307 | 308 => {
                    let loc = resp.headers().get("location").and_then(|v| v.to_str().ok()).ok_or_else(|| http(&url, "a redirect with no location"))?;
                    url = url.join(loc).map_err(|e| http(&url, e))?;
                }
                401 if same_host && !retried_auth => {
                    let challenge = resp
                        .headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .and_then(parse_challenge)
                        .ok_or_else(|| RegistryError::Auth(format!("{url}: 401 without a bearer challenge")))?;
                    let token = self.token_for(r, &challenge).await?;
                    self.token = Some((r.repository.clone(), token));
                    retried_auth = true;
                }
                _ => return Err(RegistryError::Status { url: url.to_string(), status }),
            }
        }
        Err(http(&url, "too many redirects"))
    }

    async fn token_for(&self, r: &Reference, c: &Challenge) -> Result<String, RegistryError> {
        let mut url = Url::parse(&c.realm).map_err(|e| RegistryError::Auth(e.to_string()))?;
        {
            let mut q = url.query_pairs_mut();
            if let Some(s) = &c.service {
                q.append_pair("service", s);
            }
            let scope = c.scope.clone().unwrap_or_else(|| format!("repository:{}:pull", r.repository));
            q.append_pair("scope", &scope);
        }
        let resp = self.get(&url, "application/json", None).await?;
        if resp.status() != 200 {
            return Err(RegistryError::Status { url: url.to_string(), status: resp.status().as_u16() });
        }
        let body = Limited::new(resp.into_body(), TOKEN_BYTES_MAX).collect().await.map_err(|_| RegistryError::TooLarge("a token answer"))?;
        let v: serde_json::Value = serde_json::from_slice(&body.to_bytes()).map_err(|e| RegistryError::Auth(e.to_string()))?;
        v.get("token")
            .or_else(|| v.get("access_token"))
            .and_then(|t| t.as_str())
            .map(str::to_string)
            .ok_or_else(|| RegistryError::Auth("a token answer with no token".into()))
    }

    fn url(&self, r: &Reference, kind: &str, reference: &str) -> Result<Url, RegistryError> {
        let s = format!("https://{}/v2/{}/{kind}/{reference}", r.registry, r.repository);
        Url::parse(&s).map_err(|e| RegistryError::Http { url: s, message: e.to_string() })
    }

    async fn document(&mut self, r: &Reference, url: Url, accept: &str) -> Result<(Vec<u8>, String), RegistryError> {
        let resp = self.fetch(r, url, accept).await?;
        let content_type = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let body = Limited::new(resp.into_body(), DOCUMENT_BYTES_MAX).collect().await.map_err(|_| RegistryError::TooLarge("a manifest"))?;
        Ok((body.to_bytes().to_vec(), content_type))
    }

    /// The image's manifest for `os`/`arch` and its config, every digest
    /// checked.
    pub async fn pull(&mut self, r: &Reference, os: &str, arch: &str) -> Result<Pulled, RegistryError> {
        let accept = [INDEX_TYPES, MANIFEST_TYPES].concat().join(", ");
        let (bytes, content_type) = self.document(r, self.url(r, "manifests", &r.manifest_ref())?, &accept).await?;
        if let Some(pinned) = &r.digest {
            pinned.check(&bytes)?;
        }
        let (manifest_digest, bytes) = if INDEX_TYPES.iter().any(|t| content_type.starts_with(t)) {
            let d = manifest::select(&bytes, os, arch)?;
            let (m, _) = self.document(r, self.url(r, "manifests", &d.digest.to_string())?, &MANIFEST_TYPES.join(", ")).await?;
            d.digest.check(&m)?;
            if m.len() as u64 != d.size {
                return Err(DigestError::Size { expected: d.size, got: m.len() as u64 }.into());
            }
            (d.digest, m)
        } else {
            (Digest::of(&bytes), bytes)
        };
        let manifest = manifest::parse_manifest(&bytes)?;
        if manifest.config.size > DOCUMENT_BYTES_MAX as u64 {
            return Err(RegistryError::TooLarge("an image config"));
        }
        let (config_bytes, _) = self.document(r, self.url(r, "blobs", &manifest.config.digest.to_string())?, "*/*").await?;
        manifest.config.digest.check(&config_bytes)?;
        let config = manifest::parse_config(&config_bytes, os, arch)?;
        Ok(Pulled { manifest_digest, manifest, config })
    }

    /// The blob at `store/sha256/<hex>`, downloaded if it is not there yet,
    /// and checked again either way before it is handed out.
    pub async fn blob(&mut self, r: &Reference, d: &Descriptor, store: &Path) -> Result<PathBuf, RegistryError> {
        let dir = store.join("sha256");
        tokio::fs::create_dir_all(&dir).await.map_err(|source| RegistryError::Io { what: "the blob store", source })?;
        let path = dir.join(d.digest.hex());
        if !path.exists() {
            let tmp = dir.join(format!("{}.part", d.digest.hex()));
            let resp = self.fetch(r, self.url(r, "blobs", &d.digest.to_string())?, "*/*").await?;
            let mut body = resp.into_body();
            let mut file = tokio::fs::File::create(&tmp).await.map_err(|source| RegistryError::Io { what: "a blob", source })?;
            let mut h = Hasher::default();
            // Bounded by the descriptor's size: a longer body is refused.
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|e| RegistryError::Http { url: d.digest.to_string(), message: e.to_string() })?;
                if let Ok(data) = frame.into_data() {
                    if h.bytes() + data.len() as u64 > d.size {
                        let _ = tokio::fs::remove_file(&tmp).await;
                        return Err(DigestError::Size { expected: d.size, got: h.bytes() + data.len() as u64 }.into());
                    }
                    h.update(&data);
                    file.write_all(&data).await.map_err(|source| RegistryError::Io { what: "a blob", source })?;
                }
            }
            file.sync_all().await.map_err(|source| RegistryError::Io { what: "a blob", source })?;
            if let Err(e) = h.finish(&d.digest, d.size) {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(e.into());
            }
            tokio::fs::rename(&tmp, &path).await.map_err(|source| RegistryError::Io { what: "a blob", source })?;
        }
        check_file(&path, &d.digest, d.size).map_err(|source| RegistryError::Io { what: "rechecking a blob", source })??;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges() {
        let c = parse_challenge(r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/busybox:pull""#).unwrap();
        assert_eq!(c.realm, "https://auth.docker.io/token");
        assert_eq!(c.service.as_deref(), Some("registry.docker.io"));
        assert_eq!(c.scope.as_deref(), Some("repository:library/busybox:pull"));
        assert_eq!(parse_challenge(r#"Bearer realm="https://ghcr.io/token""#).unwrap().service, None);
        assert!(parse_challenge(r#"Basic realm="x""#).is_none());
        assert!(parse_challenge(r#"Bearer realm="http://plain/token""#).is_none(), "a token over plain HTTP");
        assert!(parse_challenge(r#"Bearer realm=https://x"#).is_none());
    }
}
