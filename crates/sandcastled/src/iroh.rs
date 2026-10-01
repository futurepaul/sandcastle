//! A computer reached by its key (fragment-next docs/runtime-seam.md): each
//! computer the node holds has an iroh endpoint here, on the host, whose
//! key is derived from the node's own. The key never enters the guest, a
//! restored snapshot cannot rewind it, and the endpoint is awake while its
//! computer sleeps: a peer's connection wakes it as a request to its URL
//! does.
//!
//! A connection (ALPN `sandcastle/1`) opens with an admission: a signed
//! note that this peer may reach this computer on this node until a time
//! (`sandcastle_nip98::verify_admission`), signed by one of the node's
//! `--admitter`s, or by the computer's owner when it lists none. Then each
//! bidirectional stream is one HTTP/1.1 connection to the computer's
//! service, served by the router's own path from its gate on (activity,
//! wake, hold, forward, upgrades: `proxy::pass`). A stream's first byte
//! says which it is. The connection closes when its admission ends; a
//! peer sends another before then to stay.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, RelayMode, RelayUrl, SecretKey};
use sandcastle_core::model::{ComputerId, Desired};
use sandcastle_nip98::{Admission, AuthError};
use sandcastle_node::gates::World;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::daemon::Daemon;

pub const ALPN: &[u8] = b"sandcastle/1";
/// A stream's first byte: an admission, or an HTTP/1.1 connection.
pub const STREAM_ADMISSION: u8 = b'A';
pub const STREAM_HTTP: u8 = b'H';
/// The longest an admission may last; a peer asks for another before.
pub const ADMISSION_LIFETIME_MAX_S: i64 = 600;
/// How long after connecting a peer has to be admitted.
const HELLO_DEADLINE: Duration = Duration::from_secs(10);
/// How often an admitted connection looks at whether its admission ended.
const EXPIRY_LOOK_EVERY: Duration = Duration::from_secs(1);
/// How often the endpoints are matched to the computers when nothing
/// changed (a made or deleted computer changes the store, which wakes it).
const RECONCILE_EVERY: Duration = Duration::from_secs(5);
/// The request line and headers, together, as the router's listener.
const HEADER_BYTES_MAX: usize = 64 * 1024;
const HEADER_READ_DEADLINE: Duration = Duration::from_secs(15);
/// What closes a connection whose admission ended, or that had none.
const CLOSE_NOT_ADMITTED: u32 = 403;
/// How long a refusal's answer is given to reach its peer before the
/// connection closes.
const ANSWER_ARRIVES_WITHIN: Duration = Duration::from_secs(2);

/// The node's iroh side: its key, its relay, and each computer's endpoint.
pub struct Iroh {
    /// The node's secret key (32 bytes), which each computer's key is
    /// derived from. Never printed: no Debug.
    secret: [u8; 32],
    /// The node's public key (64 hex): what an admission names.
    pub node: String,
    pub relay: Option<RelayUrl>,
    endpoints: Mutex<HashMap<ComputerId, Endpoint>>,
}

impl Iroh {
    /// From the node's secret key (64 hex) and its relay.
    pub fn new(node_secret_hex: &str, relay: Option<RelayUrl>) -> Option<Iroh> {
        let secret: [u8; 32] = hex::decode(node_secret_hex.trim()).ok()?.try_into().ok()?;
        let node = sandcastle_nip98::Keys::from_secret_hex(node_secret_hex)?.pubkey_hex().to_string();
        Some(Iroh { secret, node, relay, endpoints: Mutex::new(HashMap::new()) })
    }

    /// A computer's iroh key: HKDF-SHA256 of the node's key and the
    /// computer's id, so it holds across restarts, differs per computer,
    /// and a computer made again (a new id) gets a new one.
    pub fn secret_key(&self, id: ComputerId) -> SecretKey {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"sandcastle iroh computer key v1"), &self.secret);
        let mut okm = [0u8; 32];
        hk.expand(id.hex().as_bytes(), &mut okm).expect("32 bytes is a valid HKDF-SHA256 output");
        SecretKey::from_bytes(&okm)
    }

    /// A computer's endpoint id (64 hex): what a peer dials.
    pub fn endpoint_id(&self, id: ComputerId) -> String {
        self.secret_key(id).public().to_string()
    }

    /// The computer's endpoint, once the node has bound it.
    pub fn endpoint(&self, id: ComputerId) -> Option<Endpoint> {
        self.endpoints.lock().expect("panics abort").get(&id).cloned()
    }

    pub fn view(&self, id: ComputerId) -> sandcastle_proto::IrohAddr {
        sandcastle_proto::IrohAddr { endpoint: self.endpoint_id(id), relay: self.relay.as_ref().map(|r| r.to_string()) }
    }
}

/// Why an admission does not let this peer in here.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    Invalid(AuthError),
    /// Signed by a key the node does not take admissions from.
    Signer,
    /// For another peer, computer, or node.
    Peer,
    Computer,
    Node,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Invalid(e) => write!(f, "{e}"),
            Refused::Signer => write!(f, "the admission's signer admits no one here"),
            Refused::Peer => write!(f, "the admission is for another peer"),
            Refused::Computer => write!(f, "the admission is for another computer"),
            Refused::Node => write!(f, "the admission is for another node"),
        }
    }
}

/// Whether `a` lets `peer` reach the computer `name` (whose owner is
/// `owner`) on `node`: signed by one of the node's `admitters`, or by the
/// computer's owner when it lists none.
pub fn admits(a: &Admission, peer: &str, name: &str, owner: &str, node: &str, admitters: &[String]) -> Result<(), Refused> {
    let signer_ok = if admitters.is_empty() { a.signer == owner } else { admitters.contains(&a.signer) };
    if !signer_ok {
        return Err(Refused::Signer);
    }
    if a.peer != peer {
        return Err(Refused::Peer);
    }
    if a.computer != name {
        return Err(Refused::Computer);
    }
    if a.node != node {
        return Err(Refused::Node);
    }
    Ok(())
}

/// Keeps an endpoint bound for each computer the node holds, until the
/// process ends.
pub async fn run<W: World>(d: Arc<Daemon<W>>) {
    assert!(d.iroh.is_some(), "iroh runs only on a node that serves it");
    let mut changed = d.node.changed.subscribe();
    // Intentionally unbounded: the node's lifetime.
    loop {
        if let Err(e) = reconcile(&d).await {
            eprintln!("iroh: {e}");
        }
        let _ = tokio::time::timeout(RECONCILE_EVERY, changed.changed()).await;
    }
}

async fn reconcile<W: World>(d: &Arc<Daemon<W>>) -> Result<(), String> {
    let iroh = d.iroh.as_ref().expect("checked by run");
    let mut wanted = Vec::new();
    for id in d.node.store.ids().map_err(|e| e.to_string())? {
        if d.node.store.load(id).map_err(|e| e.to_string())?.is_some_and(|c| c.desired != Desired::Deleted) {
            wanted.push(id);
        }
    }
    let gone: Vec<(ComputerId, Endpoint)> = {
        let mut eps = iroh.endpoints.lock().expect("panics abort");
        let gone_ids: Vec<ComputerId> = eps.keys().filter(|id| !wanted.contains(id)).copied().collect();
        gone_ids.into_iter().filter_map(|id| eps.remove(&id).map(|e| (id, e))).collect()
    };
    for (_, ep) in gone {
        ep.close().await;
    }
    for id in wanted {
        if iroh.endpoint(id).is_some() {
            continue;
        }
        let relay = match &iroh.relay {
            Some(url) => RelayMode::Custom(url.clone().into()),
            None if d.config.iroh_without_relay => RelayMode::Disabled,
            None => unreachable!("a node with iroh has a relay, or runs its tests"),
        };
        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(iroh.secret_key(id))
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(relay)
            .bind()
            .await
            .map_err(|e| format!("binding computer {}'s endpoint: {e}", id.hex()))?;
        iroh.endpoints.lock().expect("panics abort").insert(id, ep.clone());
        tokio::spawn(accept(d.clone(), ep, id));
    }
    Ok(())
}

/// A computer's endpoint's connections, until it closes.
async fn accept<W: World>(d: Arc<Daemon<W>>, ep: Endpoint, id: ComputerId) {
    // Bounded by the endpoint: None once it closes.
    while let Some(incoming) = ep.accept().await {
        let d = d.clone();
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                connection(d, conn, id).await;
            }
        });
    }
}

fn now_s<W: World>(d: &Daemon<W>) -> i64 {
    i64::try_from(d.now() / 1000).expect("milliseconds since the epoch fit in i64")
}

/// One peer's connection: admitted by its first stream within the hello
/// deadline, then its streams served while an admission holds.
async fn connection<W: World>(d: Arc<Daemon<W>>, conn: Connection, id: ComputerId) {
    let peer = conn.remote_id().to_string();
    let hello = tokio::time::Instant::now() + HELLO_DEADLINE;
    let mut until_s: i64 = 0;
    let mut look = tokio::time::interval(EXPIRY_LOOK_EVERY);
    // Bounded by the connection: it ends when the peer goes, or when its
    // admission does.
    loop {
        tokio::select! {
            stream = conn.accept_bi() => {
                let Ok((send, mut recv)) = stream else { return };
                let mut kind = [0u8; 1];
                if recv.read_exact(&mut kind).await.is_err() {
                    continue;
                }
                match kind[0] {
                    STREAM_ADMISSION => match admission(&d, id, &peer, send, recv).await {
                        Some(exp) => until_s = until_s.max(exp),
                        None if until_s == 0 => {
                            conn.close(CLOSE_NOT_ADMITTED.into(), b"not admitted");
                            return;
                        }
                        None => {}
                    },
                    STREAM_HTTP if now_s(&d) < until_s => {
                        tokio::spawn(http(d.clone(), id, send, recv));
                    }
                    _ => {
                        conn.close(CLOSE_NOT_ADMITTED.into(), b"not admitted");
                        return;
                    }
                }
            }
            _ = look.tick() => {
                let ended = if until_s == 0 { tokio::time::Instant::now() >= hello } else { now_s(&d) >= until_s };
                if ended {
                    conn.close(CLOSE_NOT_ADMITTED.into(), b"admission ended");
                    return;
                }
            }
        }
    }
}

/// An admission stream: `u16` length, the admission's JSON; answered with
/// `u16` length and JSON (`{"admitted": true, "until": s}`, or `false` and
/// why). Its end, when it admits.
async fn admission<W: World>(d: &Daemon<W>, id: ComputerId, peer: &str, mut send: SendStream, mut recv: RecvStream) -> Option<i64> {
    let decided = async {
        let len = recv.read_u16().await.map_err(|_| "a length".to_string())?;
        if usize::from(len) > sandcastle_nip98::ADMISSION_BYTES_MAX {
            return Err(Refused::Invalid(AuthError::TooLarge).to_string());
        }
        let mut raw = vec![0u8; usize::from(len)];
        recv.read_exact(&mut raw).await.map_err(|_| "the admission".to_string())?;
        let window = i64::try_from(d.config.auth_window_s).expect("checked: 1 to 600");
        let a = sandcastle_nip98::verify_admission(&raw, now_s(d), window, ADMISSION_LIFETIME_MAX_S).map_err(|e| Refused::Invalid(e).to_string())?;
        let computer = match d.node.store.load(id) {
            Ok(Some(c)) if c.desired != Desired::Deleted => c,
            Ok(_) => return Err("no such computer".to_string()),
            Err(e) => return Err(format!("the node could not read its state: {e}")),
        };
        let iroh = d.iroh.as_ref().expect("a connection comes from an iroh endpoint");
        admits(&a, peer, &computer.name, &computer.owner, &iroh.node, &d.config.admitters).map_err(|r| r.to_string())?;
        Ok(a.expires_at)
    };
    let answer = match decided.await {
        Ok(until) => (Some(until), serde_json::json!({"admitted": true, "until": until})),
        Err(why) => (None, serde_json::json!({"admitted": false, "reason": why})),
    };
    let body = answer.1.to_string();
    let len = u16::try_from(body.len()).expect("an answer is a short JSON object");
    let _ = send.write_u16(len).await;
    let _ = send.write_all(body.as_bytes()).await;
    let _ = send.finish();
    if answer.0.is_none() {
        // A refusal may close the connection next; closing discards what the
        // peer has not acknowledged, so the answer is let arrive first.
        let _ = tokio::time::timeout(ANSWER_ARRIVES_WITHIN, send.stopped()).await;
    }
    answer.0
}

/// An HTTP/1.1 stream, served by the router's path from its gate on, in one
/// of the node's connection slots.
async fn http<W: World>(d: Arc<Daemon<W>>, id: ComputerId, send: SendStream, recv: RecvStream) {
    let Ok(slot) = d.slots.clone().try_acquire_owned() else { return };
    let svc = hyper::service::service_fn(move |req| {
        let d = d.clone();
        async move { Ok::<_, std::convert::Infallible>(crate::proxy::pass(&d, id, req).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_READ_DEADLINE)
        .max_buf_size(HEADER_BYTES_MAX)
        .serve_connection(hyper_util::rt::TokioIo::new(tokio::io::join(recv, send)), svc)
        .with_upgrades()
        .await;
    drop(slot);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandcastle_nip98::Keys;

    fn admission(signer: &Keys, peer: &str, computer: &str, node: &str) -> Admission {
        let raw = signer.admission(peer, computer, node, 1_000, 1_300);
        sandcastle_nip98::verify_admission(raw.as_bytes(), 1_000, 60, ADMISSION_LIFETIME_MAX_S).unwrap()
    }

    /// Goal: an admission admits one peer to one computer on one node, from
    /// the right signer only. Method: a computer owned by `owner`, each
    /// field wrong in turn, with and without the node's own admitters.
    #[test]
    fn who_may_admit_whom() {
        let (owner, admitter, stranger) = (Keys::generate(), Keys::generate(), Keys::generate());
        let o = owner.pubkey_hex();
        let (peer, node) = ("1".repeat(64), "2".repeat(64));
        let ok = admission(&owner, &peer, "hermes", &node);
        assert_eq!(admits(&ok, &peer, "hermes", o, &node, &[]), Ok(()), "the owner admits when the node names no admitter");
        assert_eq!(admits(&admission(&stranger, &peer, "hermes", &node), &peer, "hermes", o, &node, &[]), Err(Refused::Signer));
        assert_eq!(admits(&ok, &"3".repeat(64), "hermes", o, &node, &[]), Err(Refused::Peer));
        assert_eq!(admits(&admission(&owner, &peer, "other", &node), &peer, "hermes", o, &node, &[]), Err(Refused::Computer));
        assert_eq!(admits(&admission(&owner, &peer, "hermes", &"3".repeat(64)), &peer, "hermes", o, &node, &[]), Err(Refused::Node));
        // a node that names its admitters takes theirs, and not the owner's
        let admitters = vec![admitter.pubkey_hex().to_string()];
        assert_eq!(admits(&ok, &peer, "hermes", o, &node, &admitters), Err(Refused::Signer), "the platform that manages it cannot admit itself");
        assert_eq!(admits(&admission(&admitter, &peer, "hermes", &node), &peer, "hermes", o, &node, &admitters), Ok(()));
    }

    /// Goal: a computer's key holds across restarts, differs per computer
    /// and per node, and is not the node's. Method: derive it twice.
    #[test]
    fn keys_are_derived_per_computer() {
        let node = Keys::generate();
        let a = Iroh::new(&node.secret_hex(), None).unwrap();
        let again = Iroh::new(&format!("{}\n", node.secret_hex()), None).unwrap();
        let other_node = Iroh::new(&Keys::generate().secret_hex(), None).unwrap();
        let (x, y) = (ComputerId::from_bytes([1; 8]), ComputerId::from_bytes([2; 8]));
        assert_eq!(a.endpoint_id(x), again.endpoint_id(x));
        assert_ne!(a.endpoint_id(x), a.endpoint_id(y));
        assert_ne!(a.endpoint_id(x), other_node.endpoint_id(x));
        assert_ne!(a.endpoint_id(x), a.node);
        assert_eq!(a.node, node.pubkey_hex());
        assert_eq!(a.endpoint_id(x).len(), 64);
        assert!(Iroh::new("nope", None).is_none());
    }
}
