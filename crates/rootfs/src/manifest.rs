//! Manifests, indexes, and image configs: what a registry says an image
//! is, parsed and checked against the limits before anything is fetched.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::digest::Digest;
use crate::LAYERS_MAX;

pub const INDEX_TYPES: &[&str] =
    &["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"];
pub const MANIFEST_TYPES: &[&str] =
    &["application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"];

/// The OCI platform of the images a node runs: KVM boots a guest of its
/// host's own architecture only, so a node pulls and loads that one.
pub const HOST_OS: &str = "linux";
#[cfg(target_arch = "x86_64")]
pub const HOST_ARCH: &str = "amd64";
#[cfg(target_arch = "aarch64")]
pub const HOST_ARCH: &str = "arm64";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("sandcastle's nodes are x86_64 or aarch64");

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Platform {
    pub architecture: String,
    pub os: String,
    #[serde(default)]
    pub variant: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: Digest,
    pub size: u64,
    #[serde(default)]
    pub platform: Option<Platform>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Index {
    pub manifests: Vec<Descriptor>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

/// The parts of an image's config a VM's start needs.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageConfig {
    #[serde(rename = "Entrypoint", default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd", default)]
    pub cmd: Option<Vec<String>>,
    #[serde(rename = "Env", default)]
    pub env: Option<Vec<String>>,
    #[serde(rename = "WorkingDir", default)]
    pub working_dir: Option<String>,
    #[serde(rename = "User", default)]
    pub user: Option<String>,
    #[serde(rename = "ExposedPorts", default)]
    pub exposed_ports: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Clone, Debug, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    config: ImageConfig,
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    os: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("malformed {what}: {message}")]
    Malformed { what: &'static str, message: String },
    #[error("no {os}/{arch} image in the index")]
    NoPlatform { os: String, arch: String },
    #[error("an image of {0} layers passes the limit of {LAYERS_MAX}")]
    TooManyLayers(usize),
    #[error("unsupported media type {0}")]
    MediaType(String),
    #[error("the image is for {os}/{arch}")]
    WrongPlatform { os: String, arch: String },
}

fn json<T: for<'de> Deserialize<'de>>(what: &'static str, bytes: &[u8]) -> Result<T, ManifestError> {
    // serde's message names a position, not the bytes, so it is safe to keep.
    serde_json::from_slice(bytes).map_err(|e| ManifestError::Malformed { what, message: e.to_string() })
}

/// The manifest for `os`/`arch` in an index.
pub fn select(index_bytes: &[u8], os: &str, arch: &str) -> Result<Descriptor, ManifestError> {
    let index: Index = json("index", index_bytes)?;
    index
        .manifests
        .into_iter()
        .find(|d| {
            MANIFEST_TYPES.contains(&d.media_type.as_str())
                && d.platform.as_ref().is_some_and(|p| p.os == os && p.architecture == arch)
        })
        .ok_or(ManifestError::NoPlatform { os: os.into(), arch: arch.into() })
}

pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, ManifestError> {
    let m: Manifest = json("manifest", bytes)?;
    if m.layers.len() > LAYERS_MAX {
        return Err(ManifestError::TooManyLayers(m.layers.len()));
    }
    for l in &m.layers {
        if !l.media_type.contains("tar") {
            return Err(ManifestError::MediaType(l.media_type.clone()));
        }
    }
    Ok(m)
}

pub fn parse_config(bytes: &[u8], os: &str, arch: &str) -> Result<ImageConfig, ManifestError> {
    let c: ConfigFile = json("config", bytes)?;
    if c.os != os || c.architecture != arch {
        return Err(ManifestError::WrongPlatform { os: c.os, arch: c.architecture });
    }
    Ok(c.config)
}

impl ImageConfig {
    /// The process a container of this image runs: its entrypoint and
    /// command, as Docker joins them.
    pub fn argv(&self) -> Vec<String> {
        let mut v = self.entrypoint.clone().unwrap_or_default();
        v.extend(self.cmd.clone().unwrap_or_default());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn selects_platform() {
        let index = format!(
            r#"{{"manifests":[
              {{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{D}","size":1,"platform":{{"architecture":"arm64","os":"linux"}}}},
              {{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{D}","size":2,"platform":{{"architecture":"amd64","os":"linux"}}}}]}}"#
        );
        assert_eq!(select(index.as_bytes(), "linux", "amd64").unwrap().size, 2);
        assert!(matches!(select(index.as_bytes(), "linux", "s390x"), Err(ManifestError::NoPlatform { .. })));
    }

    #[test]
    fn manifest_limits() {
        let layer = format!(r#"{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{D}","size":3}}"#);
        let m = |n: usize, mt: &str| {
            format!(
                r#"{{"config":{{"mediaType":"x","digest":"{D}","size":1}},"layers":[{}]}}"#,
                vec![layer.replace("application/vnd.oci.image.layer.v1.tar+gzip", mt); n].join(",")
            )
        };
        assert_eq!(parse_manifest(m(2, "application/vnd.oci.image.layer.v1.tar+gzip").as_bytes()).unwrap().layers.len(), 2);
        assert_eq!(parse_manifest(m(LAYERS_MAX + 1, "application/vnd.oci.image.layer.v1.tar").as_bytes()), Err(ManifestError::TooManyLayers(LAYERS_MAX + 1)));
        assert!(matches!(parse_manifest(m(1, "application/x-helm").as_bytes()), Err(ManifestError::MediaType(_))));
        assert!(matches!(parse_manifest(b"{"), Err(ManifestError::Malformed { .. })));
    }

    #[test]
    fn config_argv() {
        let c = parse_config(
            br#"{"architecture":"amd64","os":"linux","config":{"Entrypoint":["/init"],"Cmd":["serve"],"Env":["A=1"]}}"#,
            "linux",
            "amd64",
        )
        .unwrap();
        assert_eq!(c.argv(), vec!["/init", "serve"]);
        assert!(parse_config(br#"{"architecture":"arm64","os":"linux"}"#, "linux", "amd64").is_err());
    }
}
