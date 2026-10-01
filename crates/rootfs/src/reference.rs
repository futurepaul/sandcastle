//! Image references as Docker writes them: `busybox`, `nousresearch/
//! hermes-agent:v2026.9.24`, `ghcr.io/o/r@sha256:…`.

use thiserror::Error;

use crate::digest::Digest;

pub const REFERENCE_BYTES_MAX: usize = 256;
const DOCKER_HUB: &str = "registry-1.docker.io";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    /// The registry's host, with a port if it has one.
    pub registry: String,
    pub repository: String,
    /// A tag, or a digest to pin.
    pub tag: String,
    pub digest: Option<Digest>,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("not an image reference: {0:.80}")]
pub struct ReferenceError(String);

impl Reference {
    pub fn parse(s: &str) -> Result<Reference, ReferenceError> {
        let bad = || ReferenceError(s.into());
        if s.is_empty() || s.len() > REFERENCE_BYTES_MAX || s.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()) {
            return Err(bad());
        }
        let (rest, digest) = match s.split_once('@') {
            Some((r, d)) => (r, Some(Digest::parse(d).map_err(|_| bad())?)),
            None => (s, None),
        };
        // A first component with a '.' or ':' (or "localhost") is a registry.
        let (registry, path) = match rest.split_once('/') {
            Some((first, more)) if first.contains('.') || first.contains(':') || first == "localhost" => {
                (first.to_string(), more.to_string())
            }
            _ => (DOCKER_HUB.to_string(), rest.to_string()),
        };
        let registry = if registry == "docker.io" { DOCKER_HUB.to_string() } else { registry };
        // A ':' after the last '/' starts the tag.
        let (repository, tag) = match path.rfind(':') {
            Some(i) if !path[i..].contains('/') => (path[..i].to_string(), path[i + 1..].to_string()),
            _ => (path, "latest".to_string()),
        };
        let repository = if registry == DOCKER_HUB && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository
        };
        let ok_component = |c: &str| {
            !c.is_empty()
                && c.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
                && !c.starts_with(['.', '_', '-'])
        };
        let (host, port) = match registry.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (registry.as_str(), None),
        };
        let ok_label = |l: &str| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') && !l.starts_with('-');
        if !host.split('.').all(ok_label) || port.is_some_and(|p| p.parse::<u16>().is_err()) {
            return Err(bad());
        }
        if !repository.split('/').all(ok_component)
            || tag.is_empty()
            || tag.len() > 128
            || !tag.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(bad());
        }
        Ok(Reference { registry, repository, tag, digest })
    }

    /// What a manifest request names: the digest if pinned, else the tag.
    pub fn manifest_ref(&self) -> String {
        match &self.digest {
            Some(d) => d.to_string(),
            None => self.tag.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_forms() {
        let r = Reference::parse("busybox").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.tag.as_str()), (DOCKER_HUB, "library/busybox", "latest"));
        let r = Reference::parse("nousresearch/hermes-agent:v2026.9.24").unwrap();
        assert_eq!((r.repository.as_str(), r.tag.as_str()), ("nousresearch/hermes-agent", "v2026.9.24"));
        let r = Reference::parse("ghcr.io/o/r:1").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str()), ("ghcr.io", "o/r"));
        let r = Reference::parse("localhost:5000/x").unwrap();
        assert_eq!((r.registry.as_str(), r.tag.as_str()), ("localhost:5000", "latest"));
        let d = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let r = Reference::parse(&format!("busybox@{d}")).unwrap();
        assert_eq!(r.manifest_ref(), d);
        assert_eq!(Reference::parse("docker.io/library/alpine:3").unwrap().registry, DOCKER_HUB);
    }

    #[test]
    fn refuses() {
        for bad in ["", "Busybox", "a b", "x:", "x@sha256:12", "../x", "x/:y", &"a".repeat(REFERENCE_BYTES_MAX + 1)] {
            assert!(Reference::parse(bad).is_err(), "{bad}");
        }
    }
}
