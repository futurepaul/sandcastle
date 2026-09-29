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
    /// spends outbound: those come from the credential source and never
    /// enter the guest (docs/sandbox.md, Credentials).
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
    /// `https://<name>.<domain>/`
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ComputerList {
    pub computers: Vec<ComputerView>,
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
        Ok(())
    }

    /// Whether this computer may become `other`: everything fixed for a
    /// computer's life is the same (its storage and its size), and
    /// something that can change did (the image, the service, or who the
    /// URL admits). A new image or service rebases the machine onto its
    /// disk; the size is fixed until resizing is built.
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
