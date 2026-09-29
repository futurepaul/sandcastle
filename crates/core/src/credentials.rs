//! Credentials as the core sees them: their shape and a digest of their
//! values, which is all a row may hold of them.

use sandcastle_proto::Credential;

use crate::model::{CredentialShape, Held};

/// What the guest sees in place of a credential with no placeholder of its
/// own: microsandbox's convention, which its swap replaces.
pub fn placeholder(c: &Credential) -> String {
    match &c.placeholder {
        Some(p) => p.clone(),
        None => format!("$MSB_{}", c.name),
    }
}

/// The dead value a withdrawn credential is swapped for: the hosts refuse
/// it, and the guest sees nothing change.
pub const WITHDRAWN: &str = "withdrawn-by-its-source";

/// A digest of the credentials, values included, in order: length-prefixed
/// so no two lists digest alike.
pub fn digest(credentials: &[Credential]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    for c in credentials {
        let placeholder = placeholder(c);
        let parts = [c.name.as_str(), c.value.as_str(), placeholder.as_str()];
        for part in parts.into_iter().chain(c.hosts.iter().map(String::as_str)) {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part.as_bytes());
        }
        h.update([0xff]);
    }
    h.finalize().into()
}

pub fn shape(credentials: &[Credential]) -> Vec<CredentialShape> {
    credentials.iter().map(|c| CredentialShape { name: c.name.clone(), hosts: c.hosts.clone(), placeholder: placeholder(c) }).collect()
}

pub fn held(credentials: &[Credential], withdrawn: bool) -> Held {
    Held { digest: digest(credentials), shape: shape(credentials), withdrawn }
}

/// The same shape with dead values: what a machine is swapped to when its
/// source refuses.
pub fn dead(shape: &[CredentialShape]) -> Vec<Credential> {
    shape
        .iter()
        .map(|s| Credential { name: s.name.clone(), value: WITHDRAWN.to_string(), hosts: s.hosts.clone(), placeholder: Some(s.placeholder.clone()) })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(name: &str, value: &str, host: &str) -> Credential {
        Credential { name: name.into(), value: value.into(), hosts: vec![host.into()], placeholder: None }
    }

    #[test]
    fn digests_see_values_order_and_boundaries() {
        let a = [cred("A_KEY", "one", "a.example")];
        assert_eq!(digest(&a), digest(&a.clone()));
        assert_ne!(digest(&a), digest(&[cred("A_KEY", "two", "a.example")]), "a new value");
        let ab = [cred("A_KEY", "x", "a.example"), cred("B_KEY", "y", "b.example")];
        let ba = [ab[1].clone(), ab[0].clone()];
        assert_ne!(digest(&ab), digest(&ba), "the order");
        assert_ne!(digest(&[cred("A_KEY", "xy", "a.example")]), digest(&[cred("A_KEYx", "y", "a.example")]), "a boundary");
    }

    #[test]
    fn a_withdrawal_keeps_the_shape_and_changes_the_digest() {
        let live = [Credential { placeholder: Some("sk-or-v1-placeholder".into()), ..cred("A_KEY", "real", "a.example") }];
        let dead = dead(&shape(&live));
        assert_eq!(shape(&dead), shape(&live));
        assert_ne!(digest(&dead), digest(&live));
        assert_eq!(dead[0].value, WITHDRAWN);
        assert_eq!(placeholder(&cred("B_KEY", "v", "b.example")), "$MSB_B_KEY");
    }
}
