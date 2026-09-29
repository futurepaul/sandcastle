//! sandcastle's wire contract. A platform (fragment now, Finite's Core
//! later) and a person's own tools speak it to a node; nothing here names a
//! person, an organization, an agent, or an application. Principals are
//! nostr public keys; every call is NIP-98 signed.
//!
//! Every input has a limit, checked by `validate` before anything is stored.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A computer's name is a DNS label under the node's domain and part of the
/// engine's sandbox name, so it is short, lowercase, and has no `--`.
pub const NAME_BYTES_MAX: usize = 40;
pub const IMAGE_BYTES_MAX: usize = 256;
pub const VCPUS_MAX: u32 = 16;
pub const MEMORY_MIB_MIN: u32 = 256;
pub const MEMORY_MIB_MAX: u32 = 64 * 1024;
pub const DATA_GIB_MAX: u32 = 1024;
pub const PATH_BYTES_MAX: usize = 128;
pub const ARGV_ENTRIES_MAX: usize = 32;
pub const ARGV_BYTES_MAX: usize = 8 * 1024;
pub const ENV_VARS_MAX: usize = 32;
pub const ENV_VALUE_BYTES_MAX: usize = 4 * 1024;
/// Computers one grant can allow; a node holds far fewer in practice.
pub const COMPUTERS_PER_GRANT_MAX: u32 = 1000;
/// A ticket opens a computer's URL once, soon after it is minted.
pub const TICKET_TTL_S: i64 = 60;
pub const URL_BYTES_MAX: usize = 512;
/// A credential source's answer: its credentials, each value's size, each
/// one's hosts, and the whole body as read.
pub const CREDENTIALS_MAX: usize = 16;
pub const CREDENTIAL_VALUE_BYTES_MAX: usize = 8 * 1024;
pub const CREDENTIAL_HOSTS_MAX: usize = 8;
pub const CREDENTIALS_BODY_BYTES_MAX: usize = 64 * 1024;
pub const PLACEHOLDER_BYTES_MIN: usize = 8;
pub const PLACEHOLDER_BYTES_MAX: usize = 256;

/// What survives a computer's machine (docs/sandbox.md, decision 3).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Storage {
    /// The image is the system and `data_path` is a durable disk: an image
    /// change rebases onto the new image and keeps the disk.
    Data,
    /// The whole machine is durable and snapshotted; no image changes.
    /// Refused until built.
    Pet,
    /// Nothing survives removal.
    Ephemeral,
}

/// Who the router lets through to a computer's service.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UrlAuth {
    /// Only a browser holding a session from a redeemed owner ticket.
    Owner,
    /// Anyone; the service does its own auth.
    Public,
}

/// The one process a computer serves at its URL. The node launches it on
/// every boot and keeps its definition outside the machine, so nothing a
/// guest writes can change or revive it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Service {
    /// The program and its arguments, run without a shell.
    pub argv: Vec<String>,
    /// The guest port it listens on, on the guest's interface (not loopback).
    pub port: u16,
    /// A path that answers once the service is ready (any status below 500).
    pub health_path: String,
    /// The service's own settings (Hermes' dashboard login, say). The node
    /// hands them to the guest through an exec's stdin into a root-only
    /// file, never on a command line. Not for credentials the service
    /// spends outbound: those come from `credentials_url` and never enter
    /// the guest.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// The body of `PUT /v1/computers/{name}`: create, or converge to, this.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComputerSpec {
    /// An OCI image reference.
    pub image: String,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub storage: Storage,
    /// The durable disk's size, for `Data`; 0 otherwise.
    pub data_gib: u32,
    /// Where the durable disk is mounted, for `Data`; empty otherwise.
    pub data_path: String,
    pub service: Service,
    pub url_auth: UrlAuth,
    /// Where the node fetches the credentials the service spends outbound
    /// (docs/sandbox.md, Credentials): the node POSTs a `CredentialsAsk`
    /// there, NIP-98 signed with its own key, at every boot and on a
    /// schedule, and hands the answer to the engine's credential swap. The
    /// guest sees a placeholder in each credential's variable; the value
    /// reaches only the credential's hosts, in the request as it leaves.
    /// The node fetches only from the origins its operator lists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_url: Option<String>,
}

/// What a caller wants a computer to be doing.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Desired {
    Running,
    Stopped,
    /// Deletion is recorded; the computer answers 404 once its machine and
    /// disk are gone. Poll until then before calling it deleted.
    Deleted,
}

/// What the node last saw, from its own probes (never the engine's say-so
/// alone: FIN-66's canary failed on provider metadata that lied).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum Observed {
    /// No machine exists yet.
    Absent,
    Stopped,
    /// The machine is up; the service is not answering yet.
    Starting,
    /// The service answered its health path.
    Serving,
    Failed { reason: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ComputerView {
    pub name: String,
    pub owner: String,
    /// The spec, with each `service.env` value replaced by "(set)": a view
    /// never echoes a service's secrets, so it is not a body to PUT back.
    pub spec: ComputerSpec,
    pub desired: Desired,
    pub observed: Observed,
    /// True until the node has acted on the current spec and desired
    /// state: right after a PUT, `observed` still describes what ran
    /// before. Poll until this is false.
    pub pending: bool,
    /// Present while the node runs the last spec that served because this
    /// spec's image or service failed. `start` retries it; a new spec
    /// replaces it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<Rollback>,
    /// `https://<name>.<domain>/`
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Rollback {
    /// The spec's image, which failed (or whose service did).
    pub failed_image: String,
    /// The image actually running: the last one that served.
    pub running_image: String,
    pub reason: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ComputerList {
    pub computers: Vec<ComputerView>,
}

/// A snapshot shipped off the host, restorable into a new computer with
/// `PUT /v1/computers/{name}?restore=<computer_id>@<snapshot>`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BackupView {
    pub computer_id: String,
    /// The computer's name when it was shipped (it may be deleted since).
    pub computer_name: String,
    pub snapshot: String,
    /// The snapshot it is incremental from, or `None` for a whole stream.
    pub base: Option<String>,
    pub created_at: i64,
    /// Sealed bytes in the bucket.
    pub bytes: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BackupList {
    /// Oldest first.
    pub backups: Vec<BackupView>,
}

/// One of the node's snapshots of a computer's durable disk.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SnapshotView {
    /// `sc-<unix seconds>-<kind>`; kind is `auto`, `stop`, or `rebase`.
    pub name: String,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SnapshotList {
    /// Oldest first.
    pub snapshots: Vec<SnapshotView>,
}

/// What a node POSTs to a computer's `credentials_url`, NIP-98 signed with
/// its own key. The platform answers with `Credentials` for the owner (or
/// refuses); it trusts the node's word on who that is.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialsAsk {
    /// The computer's name and id on the node, and the node's name.
    pub computer: String,
    pub id: String,
    pub node: String,
    /// The key that owns the computer (64 hex).
    pub owner: String,
}

/// A credential source's answer.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub credentials: Vec<Credential>,
}

/// One credential: the variable the service reads it from (holding a
/// placeholder), its value, and the hosts it may reach.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub name: String,
    pub value: String,
    pub hosts: Vec<String>,
    /// What the service sees in place of the value, and sends; the engine
    /// swaps it for the value on the way to `hosts`. Shaped like the real
    /// thing for services that check a key's shape (Hermes takes an
    /// OpenRouter key only if it starts `sk-or-`). Without one, the
    /// engine's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
}

/// A credential's value never reaches a log.
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("name", &self.name)
            .field("value", &"(set)")
            .field("hosts", &self.hosts)
            .field("placeholder", &self.placeholder)
            .finish()
    }
}

/// The body of `PUT /v1/grants/{pubkey}`, written by a grantor: what that
/// key may hold on this node.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantSpec {
    pub computers_max: u32,
    pub vcpus_max: u32,
    pub memory_mib_max: u32,
    pub data_gib_max: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GrantView {
    pub pubkey: String,
    pub spec: GrantSpec,
    pub granted_by: String,
}

/// The answer to `POST /v1/computers/{name}/tickets`: open `url` in a
/// browser within `TICKET_TTL_S`; it works once.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub url: String,
    pub expires_at: i64,
}

/// The body of every refusal. `code` is stable; `message` is for people.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

/// Why an input was refused before anything was stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub String);

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn invalid<T>(what: impl Into<String>) -> Result<T, Invalid> {
    Err(Invalid(what.into()))
}

/// `[a-z][a-z0-9-]*`, at most `NAME_BYTES_MAX`, no `--`, not ending in `-`.
pub fn validate_name(name: &str) -> Result<(), Invalid> {
    if name.is_empty() || name.len() > NAME_BYTES_MAX {
        return invalid(format!("a name is 1 to {NAME_BYTES_MAX} characters"));
    }
    let first_is_letter = name.as_bytes()[0].is_ascii_lowercase();
    if !first_is_letter {
        return invalid("a name starts with a lowercase letter");
    }
    let charset_ok = name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
    if !charset_ok {
        return invalid("a name is lowercase letters, digits, and '-'");
    }
    if name.contains("--") || name.ends_with('-') {
        return invalid("a name has no '--' and does not end in '-'");
    }
    Ok(())
}

/// 64 lowercase hex characters: an x-only public key.
pub fn validate_pubkey(pubkey: &str) -> Result<(), Invalid> {
    let ok = pubkey.len() == 64 && pubkey.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
    if ok {
        Ok(())
    } else {
        invalid("a public key is 64 lowercase hex characters")
    }
}

fn validate_abs_path(path: &str, what: &str) -> Result<(), Invalid> {
    if path.len() > PATH_BYTES_MAX {
        return invalid(format!("{what} is at most {PATH_BYTES_MAX} bytes"));
    }
    if !path.starts_with('/') || path == "/" {
        return invalid(format!("{what} is an absolute path below /"));
    }
    let clean = path.split('/').all(|seg| seg != ".." && seg != ".");
    let printable = path.bytes().all(|c| c.is_ascii_graphic());
    if clean && printable {
        Ok(())
    } else {
        invalid(format!("{what} has no '.', '..', spaces, or control characters"))
    }
}

/// `https://` and at most `URL_BYTES_MAX` printable bytes; the node
/// parses it fully and checks its origin.
fn validate_url(url: &str, what: &str) -> Result<(), Invalid> {
    let ok = url.len() <= URL_BYTES_MAX && url.len() > "https://".len() && url.starts_with("https://") && url.bytes().all(|c| c.is_ascii_graphic());
    if ok {
        Ok(())
    } else {
        invalid(format!("{what} is an https URL of at most {URL_BYTES_MAX} printable bytes"))
    }
}

/// A DNS name, or `*.` and one: lowercase letters, digits, '-' and '.'.
fn valid_host(host: &str) -> bool {
    let name = host.strip_prefix("*.").unwrap_or(host);
    let labels_ok = name.split('.').all(|l| {
        !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    });
    !name.is_empty() && name.len() <= 253 && name.contains('.') && labels_ok
}

/// The variables a credential may be: an uppercase name ending in `_KEY`,
/// `_TOKEN`, or `_SECRET`. The node hands each value to the engine in the
/// engine's own environment, under this name, so no name may be one the
/// engine or its host reads (`PATH`, `HOME`, `MSB_*`, `LD_*`, proxies):
/// the suffix rule keeps every such name out.
pub fn valid_credential_name(name: &str) -> bool {
    let shaped = !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_uppercase()
        && name.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_');
    let suffixed = ["_KEY", "_TOKEN", "_SECRET"].iter().any(|s| name.len() > s.len() && name.ends_with(s));
    shaped && suffixed && !name.starts_with("MSB_")
}

impl Credentials {
    /// Checks a source's answer before the node uses any of it. `taken` are
    /// the service's own variables, which a credential may not shadow.
    pub fn validate(&self, taken: &BTreeMap<String, String>) -> Result<(), Invalid> {
        if self.credentials.len() > CREDENTIALS_MAX {
            return invalid(format!("at most {CREDENTIALS_MAX} credentials"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for c in &self.credentials {
            if !valid_credential_name(&c.name) {
                return invalid(format!("credential name {:?} is [A-Z][A-Z0-9_]* ending in _KEY, _TOKEN, or _SECRET, at most 64, not MSB_*", c.name));
            }
            if !seen.insert(c.name.as_str()) {
                return invalid(format!("credential {} is named twice", c.name));
            }
            if taken.contains_key(&c.name) {
                return invalid(format!("credential {} is also one of the service's own variables", c.name));
            }
            // It travels in a header: printable ASCII, no spaces.
            let value_ok = !c.value.is_empty() && c.value.len() <= CREDENTIAL_VALUE_BYTES_MAX && c.value.bytes().all(|b| b.is_ascii_graphic());
            if !value_ok {
                return invalid(format!("credential {} is 1 to {CREDENTIAL_VALUE_BYTES_MAX} printable ASCII bytes with no spaces", c.name));
            }
            if c.hosts.is_empty() || c.hosts.len() > CREDENTIAL_HOSTS_MAX {
                return invalid(format!("credential {} names 1 to {CREDENTIAL_HOSTS_MAX} hosts", c.name));
            }
            if let Some(bad) = c.hosts.iter().find(|h| !valid_host(h)) {
                return invalid(format!("credential {}: {bad:?} is not a host name (or *. and one)", c.name));
            }
            if let Some(p) = &c.placeholder {
                // Printable, and nothing the engine's config reads as syntax
                // (it interpolates `$`) or a shell or a quote would.
                let shaped = (PLACEHOLDER_BYTES_MIN..=PLACEHOLDER_BYTES_MAX).contains(&p.len())
                    && p.bytes().all(|b| b.is_ascii_graphic() && !b"$'\"`\\{}".contains(&b));
                if !shaped {
                    return invalid(format!(
                        "credential {}'s placeholder is {PLACEHOLDER_BYTES_MIN} to {PLACEHOLDER_BYTES_MAX} printable ASCII bytes without $ ' \" ` \\ {{ }}",
                        c.name
                    ));
                }
            }
        }
        // A placeholder that held a value would hand it to the guest; two
        // alike would swap one credential's value in for the other's.
        let placeholders: Vec<&str> = self.credentials.iter().filter_map(|c| c.placeholder.as_deref()).collect();
        for (i, p) in placeholders.iter().enumerate() {
            if placeholders[..i].contains(p) {
                return invalid("two credentials share a placeholder");
            }
            if self.credentials.iter().any(|c| p.contains(c.value.as_str())) {
                return invalid("a placeholder holds a credential's value");
            }
        }
        Ok(())
    }
}

impl ComputerSpec {
    pub fn validate(&self) -> Result<(), Invalid> {
        let image_ok = !self.image.is_empty()
            && self.image.len() <= IMAGE_BYTES_MAX
            && self.image.bytes().all(|c| c.is_ascii_alphanumeric() || b"./:-_@".contains(&c));
        if !image_ok {
            return invalid(format!("an image is 1 to {IMAGE_BYTES_MAX} characters of [A-Za-z0-9./:-_@]"));
        }
        if self.vcpus == 0 || self.vcpus > VCPUS_MAX {
            return invalid(format!("vcpus is 1 to {VCPUS_MAX}"));
        }
        if self.memory_mib < MEMORY_MIB_MIN || self.memory_mib > MEMORY_MIB_MAX {
            return invalid(format!("memory_mib is {MEMORY_MIB_MIN} to {MEMORY_MIB_MAX}"));
        }
        match self.storage {
            Storage::Data => {
                if self.data_gib == 0 || self.data_gib > DATA_GIB_MAX {
                    return invalid(format!("data_gib is 1 to {DATA_GIB_MAX} for data storage"));
                }
                validate_abs_path(&self.data_path, "data_path")?;
            }
            Storage::Ephemeral => {
                if self.data_gib != 0 || !self.data_path.is_empty() {
                    return invalid("ephemeral storage has no data disk: data_gib 0 and data_path empty");
                }
            }
            Storage::Pet => return invalid("pet storage is not built yet"),
        }
        let argv = &self.service.argv;
        if argv.is_empty() || argv.len() > ARGV_ENTRIES_MAX {
            return invalid(format!("service.argv has 1 to {ARGV_ENTRIES_MAX} entries"));
        }
        let argv_bytes: usize = argv.iter().map(|a| a.len()).sum();
        if argv_bytes > ARGV_BYTES_MAX {
            return invalid(format!("service.argv is at most {ARGV_BYTES_MAX} bytes in all"));
        }
        if argv.iter().any(|a| a.bytes().any(|c| c == 0)) {
            return invalid("service.argv has no NUL bytes");
        }
        validate_abs_path(&argv[0], "service.argv[0]")?;
        if self.service.env.len() > ENV_VARS_MAX {
            return invalid(format!("service.env has at most {ENV_VARS_MAX} variables"));
        }
        for (k, v) in &self.service.env {
            let name_ok = !k.is_empty()
                && k.len() <= 64
                && !k.as_bytes()[0].is_ascii_digit()
                && k.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_');
            if !name_ok {
                return invalid(format!("service.env name {k:?} is [A-Z_][A-Z0-9_]*, at most 64"));
            }
            // No NUL or newline: the node writes one `NAME='value'` line each.
            let value_ok = v.len() <= ENV_VALUE_BYTES_MAX && !v.bytes().any(|c| c == 0 || c == b'\n' || c == b'\r');
            if !value_ok {
                return invalid(format!("service.env {k} is at most {ENV_VALUE_BYTES_MAX} bytes with no NUL or newline"));
            }
        }
        if self.service.port == 0 {
            return invalid("service.port is 1 to 65535");
        }
        let health = &self.service.health_path;
        let health_ok = health.starts_with('/') && health.len() <= PATH_BYTES_MAX && health.bytes().all(|c| c.is_ascii_graphic());
        if !health_ok {
            return invalid(format!("service.health_path starts with '/' and is at most {PATH_BYTES_MAX} printable bytes"));
        }
        if let Some(url) = &self.credentials_url {
            validate_url(url, "credentials_url")?;
        }
        Ok(())
    }

    /// Whether this computer may become `other`: everything fixed for a
    /// computer's life is the same (its storage and its size), and
    /// something that can change did (the image, the service, who the URL
    /// admits, or the credential source). A new image, service, or source
    /// rebases the machine onto its disk; the size is fixed until resizing
    /// is built.
    pub fn can_become(&self, other: &ComputerSpec) -> bool {
        let fixed_same = self.storage == other.storage
            && self.data_gib == other.data_gib
            && self.data_path == other.data_path
            && self.vcpus == other.vcpus
            && self.memory_mib == other.memory_mib;
        fixed_same && self != other
    }
}

impl GrantSpec {
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.computers_max > COMPUTERS_PER_GRANT_MAX {
            return invalid(format!("computers_max is at most {COMPUTERS_PER_GRANT_MAX}"));
        }
        if self.vcpus_max > VCPUS_MAX {
            return invalid(format!("vcpus_max is at most {VCPUS_MAX} (a per-computer ceiling)"));
        }
        if self.memory_mib_max > MEMORY_MIB_MAX {
            return invalid(format!("memory_mib_max is at most {MEMORY_MIB_MAX} (a per-computer ceiling)"));
        }
        if self.data_gib_max > DATA_GIB_MAX {
            return invalid(format!("data_gib_max is at most {DATA_GIB_MAX} (a per-computer ceiling)"));
        }
        Ok(())
    }

    /// Whether one computer of `spec` fits under this grant's ceilings.
    pub fn admits(&self, spec: &ComputerSpec) -> bool {
        spec.vcpus <= self.vcpus_max && spec.memory_mib <= self.memory_mib_max && spec.data_gib <= self.data_gib_max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn hermes() -> ComputerSpec {
        ComputerSpec {
            image: "nousresearch/hermes-agent:v2026.9.24".into(),
            vcpus: 2,
            memory_mib: 4096,
            storage: Storage::Data,
            data_gib: 10,
            data_path: "/opt/data".into(),
            service: Service {
                argv: vec!["/opt/hermes/docker/entrypoint-dispatch.sh".into(), "serve".into()],
                port: 9119,
                health_path: "/api/auth/providers".into(),
                env: BTreeMap::new(),
            },
            url_auth: UrlAuth::Owner,
            credentials_url: None,
        }
    }

    #[test]
    fn names() {
        for ok in ["a", "hermes", "a1-b2", &"a".repeat(NAME_BYTES_MAX)] {
            assert_eq!(validate_name(ok), Ok(()), "{ok}");
        }
        for bad in ["", "1a", "-a", "a-", "a--b", "A", "a_b", "a.b", "a b", &"a".repeat(NAME_BYTES_MAX + 1)] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn specs_valid_and_invalid() {
        assert_eq!(hermes().validate(), Ok(()));
        type Change = Box<dyn Fn(&mut ComputerSpec)>;
        let cases: Vec<(&str, Change)> = vec![
            ("empty image", Box::new(|s| s.image.clear())),
            ("image with a space", Box::new(|s| s.image = "a b".into())),
            ("zero vcpus", Box::new(|s| s.vcpus = 0)),
            ("too many vcpus", Box::new(|s| s.vcpus = VCPUS_MAX + 1)),
            ("too little memory", Box::new(|s| s.memory_mib = MEMORY_MIB_MIN - 1)),
            ("data with no disk", Box::new(|s| s.data_gib = 0)),
            ("data at /", Box::new(|s| s.data_path = "/".into())),
            ("data path with ..", Box::new(|s| s.data_path = "/opt/../etc".into())),
            ("relative data path", Box::new(|s| s.data_path = "opt/data".into())),
            ("pet", Box::new(|s| s.storage = Storage::Pet)),
            ("ephemeral with a disk", Box::new(|s| s.storage = Storage::Ephemeral)),
            ("no argv", Box::new(|s| s.service.argv.clear())),
            ("relative program", Box::new(|s| s.service.argv[0] = "hermes".into())),
            ("NUL in argv", Box::new(|s| s.service.argv[1] = "a\0b".into())),
            ("too many args", Box::new(|s| s.service.argv = vec!["/x".into(); ARGV_ENTRIES_MAX + 1])),
            ("port 0", Box::new(|s| s.service.port = 0)),
            ("health path relative", Box::new(|s| s.service.health_path = "health".into())),
            ("lowercase env name", Box::new(|s| { s.service.env.insert("path".into(), "x".into()); })),
            ("env name with a digit first", Box::new(|s| { s.service.env.insert("1A".into(), "x".into()); })),
            ("newline in an env value", Box::new(|s| { s.service.env.insert("A".into(), "x\ny".into()); })),
            ("too many env vars", Box::new(|s| { for i in 0..=ENV_VARS_MAX { s.service.env.insert(format!("V{i}"), "x".into()); } })),
            ("plain http credentials", Box::new(|s| s.credentials_url = Some("http://platform.example/c".into()))),
            ("credentials url with a space", Box::new(|s| s.credentials_url = Some("https://platform.example/a b".into()))),
            ("bare scheme", Box::new(|s| s.credentials_url = Some("https://".into()))),
            ("long credentials url", Box::new(|s| s.credentials_url = Some(format!("https://a.example/{}", "x".repeat(URL_BYTES_MAX))))),
        ];
        for (what, change) in cases {
            let mut s = hermes();
            change(&mut s);
            assert!(s.validate().is_err(), "{what} should be refused");
        }
        let mut eph = hermes();
        eph.storage = Storage::Ephemeral;
        eph.data_gib = 0;
        eph.data_path.clear();
        assert_eq!(eph.validate(), Ok(()));
    }

    #[test]
    fn a_spec_without_a_credential_source_reads_as_before() {
        let mut v = serde_json::to_value(hermes()).unwrap();
        assert!(v.get("credentials_url").is_none(), "absent, not null");
        v.as_object_mut().unwrap().remove("credentials_url");
        assert_eq!(serde_json::from_value::<ComputerSpec>(v).unwrap(), hermes());
        let mut with = hermes();
        with.credentials_url = Some("https://platform.example/api/credentials".into());
        assert_eq!(with.validate(), Ok(()));
        assert!(hermes().can_become(&with), "a new source is a change");
    }

    fn cred(name: &str, value: &str, hosts: &[&str]) -> Credential {
        Credential { name: name.into(), value: value.into(), hosts: hosts.iter().map(|h| h.to_string()).collect(), placeholder: None }
    }

    fn placed(name: &str, value: &str, placeholder: &str) -> Credential {
        Credential { placeholder: Some(placeholder.into()), ..cred(name, value, &["a.example"]) }
    }

    #[test]
    fn credentials_valid_and_invalid() {
        let none = BTreeMap::new();
        let ok = Credentials { credentials: vec![cred("OPENROUTER_API_KEY", "sk-or-v1-abc", &["openrouter.ai"]), cred("GH_TOKEN", "t", &["*.github.com", "github.com"])] };
        assert_eq!(ok.validate(&none), Ok(()));
        let bad: Vec<(&str, Credential)> = vec![
            ("PATH", cred("PATH", "x", &["a.example"])),
            ("no suffix", cred("OPENROUTER", "x", &["a.example"])),
            ("only a suffix", cred("_KEY", "x", &["a.example"])),
            ("the engine's own", cred("MSB_REGISTRY_TOKEN", "x", &["a.example"])),
            ("lowercase", cred("api_key", "x", &["a.example"])),
            ("empty value", cred("A_KEY", "", &["a.example"])),
            ("a space in the value", cred("A_KEY", "a b", &["a.example"])),
            ("a newline in the value", cred("A_KEY", "a\nb", &["a.example"])),
            ("a long value", cred("A_KEY", &"x".repeat(CREDENTIAL_VALUE_BYTES_MAX + 1), &["a.example"])),
            ("no hosts", cred("A_KEY", "x", &[])),
            ("any host", cred("A_KEY", "x", &["*"])),
            ("a bare name", cred("A_KEY", "x", &["localhost"])),
            ("an address with a port", cred("A_KEY", "x", &["a.example:443"])),
            ("an uppercase host", cred("A_KEY", "x", &["A.example"])),
            ("too many hosts", cred("A_KEY", "x", &["a.example"; CREDENTIAL_HOSTS_MAX + 1])),
        ];
        for (what, c) in bad {
            assert!(Credentials { credentials: vec![c] }.validate(&none).is_err(), "{what} should be refused");
        }
        for (what, p) in [("short", "sk-or-1"), ("a dollar", "sk-or-v1-$HOME-x"), ("a brace", "sk-or-v1-{x}-yz"), ("a quote", "sk-or-v1-'x'-yz"), ("a space", "sk-or-v1 xyzw")] {
            assert!(Credentials { credentials: vec![placed("A_KEY", "v4lue-0123", p)] }.validate(&none).is_err(), "a placeholder with {what}");
        }
        assert_eq!(Credentials { credentials: vec![placed("A_KEY", "v4lue-0123", "sk-or-v1-sandcastle-placeholder")] }.validate(&none), Ok(()));
        let holds = Credentials { credentials: vec![placed("A_KEY", "v4lue-0123", "sk-or-v4lue-0123-x")] };
        assert!(holds.validate(&none).is_err(), "a placeholder never holds a value");
        let shared = Credentials { credentials: vec![placed("A_KEY", "one-1111", "the-same-one"), placed("B_KEY", "two-2222", "the-same-one")] };
        assert!(shared.validate(&none).is_err(), "nor is shared");
        let twice = Credentials { credentials: vec![cred("A_KEY", "x", &["a.example"]), cred("A_KEY", "y", &["a.example"])] };
        assert!(twice.validate(&none).is_err());
        let many = Credentials { credentials: (0..=CREDENTIALS_MAX).map(|i| cred(&format!("K{i}_KEY"), "x", &["a.example"])).collect() };
        assert!(many.validate(&none).is_err());
        let mut taken = BTreeMap::new();
        taken.insert("OPENROUTER_API_KEY".to_string(), "mine".to_string());
        assert!(ok.validate(&taken).is_err(), "a credential never shadows the service's own variable");
    }

    #[test]
    fn a_credential_value_never_prints() {
        let c = cred("A_KEY", "sk-very-secret", &["a.example"]);
        let shown = format!("{c:?} {:?}", Credentials { credentials: vec![c.clone()] });
        assert!(!shown.contains("sk-very-secret"), "{shown}");
        assert!(shown.contains("A_KEY"));
    }

    #[test]
    fn unknown_fields_are_refused() {
        let mut v = serde_json::to_value(hermes()).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ComputerSpec>(v).is_err());
    }

    #[test]
    fn what_a_computer_can_become() {
        let a = hermes();
        assert!(!a.can_become(&a.clone()), "the same spec is no change");
        let mut newer = hermes();
        newer.image = "nousresearch/hermes-agent:v2026.9.21".into();
        assert!(a.can_become(&newer));
        let mut env = hermes();
        env.service.env.insert("A".into(), "1".into());
        assert!(a.can_become(&env), "a service change");
        let mut public = hermes();
        public.url_auth = UrlAuth::Public;
        assert!(a.can_become(&public));
        let mut bigger = newer.clone();
        bigger.vcpus = 4;
        assert!(!a.can_become(&bigger), "the size is fixed");
        let mut moved = hermes();
        moved.data_path = "/data".into();
        assert!(!a.can_become(&moved), "the disk's mount is fixed");
    }

    #[test]
    fn grants_admit_within_ceilings() {
        let g = GrantSpec { computers_max: 2, vcpus_max: 2, memory_mib_max: 4096, data_gib_max: 10 };
        assert_eq!(g.validate(), Ok(()));
        assert!(g.admits(&hermes()));
        let mut big = hermes();
        big.memory_mib = 8192;
        assert!(!g.admits(&big));
        let too_many = GrantSpec { computers_max: COMPUTERS_PER_GRANT_MAX + 1, ..g };
        assert!(too_many.validate().is_err());
    }
}
