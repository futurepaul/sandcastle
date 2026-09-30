//! `iroh` (with `--hermes`, after it): the same Hermes reached by its key
//! (fragment-next docs/runtime-seam.md) through the node's iroh relay, from
//! here, measured beside its URL in the same run: a first contact, awake
//! requests, warm and cold wakes, a chat turn over its socket, and sleep
//! under an open connection. And the refusals, over the real relay.

use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use iroh::endpoint::{presets, Connection};
use iroh::{Endpoint, EndpointAddr, RelayMode, RelayUrl};
use serde_json::{json, Value};

use super::{rpc, secs, spread, turn, Owner, Run, Step};

const ALPN: &[u8] = b"sandcastle/1";
const STREAM_ADMISSION: u8 = b'A';
const STREAM_HTTP: u8 = b'H';
/// Samples of each wake: a warm one takes a second to set up, a cold one
/// a few more.
const WARM_SAMPLES: usize = 5;
const COLD_SAMPLES: usize = 3;
const AWAKE_SAMPLES: usize = 10;

/// An admission on its own stream: the node's answer.
async fn admit(conn: &Connection, admission: &str) -> Result<Value, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(&[STREAM_ADMISSION]).await.map_err(|e| e.to_string())?;
    send.write_u16(u16::try_from(admission.len()).map_err(|e| e.to_string())?).await.map_err(|e| e.to_string())?;
    send.write_all(admission.as_bytes()).await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    let len = recv.read_u16().await.map_err(|e| format!("the answer: {e}"))?;
    let mut body = vec![0u8; usize::from(len)];
    recv.read_exact(&mut body).await.map_err(|e| e.to_string())?;
    serde_json::from_slice(&body).map_err(|e| e.to_string())
}

/// One request over a new stream: status, headers, body.
async fn request(conn: &Connection, host: &str, method: &str, path: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Result<(u16, hyper::HeaderMap, Vec<u8>), String> {
    let (mut send, recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(&[STREAM_HTTP]).await.map_err(|e| e.to_string())?;
    let (mut sender, driver) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tokio::io::join(recv, send))).await.map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = driver.with_upgrades().await;
    });
    let mut req = Request::builder().method(method).uri(path).header("host", host);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = sender.send_request(req.body(Full::new(Bytes::from(body))).map_err(|e| e.to_string())?).await.map_err(|e| e.to_string())?;
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
    Ok((parts.status.as_u16(), parts.headers, bytes.to_vec()))
}

/// Hermes' socket over a new stream, with its protocols.
async fn websocket(conn: &Connection, host: &str, protocols: &[&str]) -> Result<(crate::ws::Ws, Option<String>), String> {
    let (mut send, recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(&[STREAM_HTTP]).await.map_err(|e| e.to_string())?;
    let (mut sender, driver) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tokio::io::join(recv, send))).await.map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = driver.with_upgrades().await;
    });
    let req = Request::get("/api/ws")
        .header("host", host)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", crate::ws::key())
        .header("sec-websocket-protocol", protocols.join(", "))
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.to_string())?;
    let mut resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
    if resp.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
        return Err(format!("the socket answered {}", resp.status()));
    }
    let chosen = resp.headers().get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).map(str::to_string);
    let io = hyper::upgrade::on(&mut resp).await.map_err(|e| format!("upgrading: {e}"))?;
    Ok((crate::ws::Ws::new(io), chosen))
}

/// The connection's selected path: through the relay, or direct.
fn path(conn: &Connection) -> String {
    let paths = conn.paths();
    let selected = paths.iter().find(|p| p.is_selected());
    match selected {
        Some(p) if p.is_relay() => format!("relayed ({} paths open)", paths.len()),
        Some(_) => format!("direct ({} paths open)", paths.len()),
        None => "no path selected".into(),
    }
}

pub async fn iroh(r: &mut Run) -> Step {
    const S: &str = "iroh";
    let name = "hermes";
    let host = format!("{name}.{}", r.client.domain);
    let (status, view) = r.view(name).await?;
    let endpoint = view["iroh"]["endpoint"].as_str().unwrap_or("").to_string();
    let relay = view["iroh"]["relay"].as_str().unwrap_or("").to_string();
    r.ensure(S, "its view names its key and its node's relay", status == 200 && endpoint.len() == 64 && !relay.is_empty(), format!("{status} {}", view["iroh"]))?;
    let node = r.evidence.node_key.clone().ok_or("the node's key, from its health")?;
    let relay: RelayUrl = relay.parse().map_err(|e| format!("the relay {relay}: {e}"))?;
    let addr = EndpointAddr::new(endpoint.parse().map_err(|e| format!("the endpoint {endpoint}: {e}"))?).with_relay_url(relay.clone());
    let bind = || Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Custom(relay.clone().into())).bind();

    // Refusals over the real relay: no admission, and someone else's.
    let stranger = bind().await.map_err(|e| e.to_string())?;
    let conn = stranger.connect(addr.clone(), ALPN).await.map_err(|e| format!("connecting: {e}"))?;
    let refused = request(&conn, &host, "GET", "/api/status", &[], vec![]).await;
    r.ensure(S, "with no admission, nothing reaches Hermes", refused.is_err(), format!("{refused:?}").chars().take(160).collect::<String>())?;
    let now = super::client::now_s();
    let conn = stranger.connect(addr.clone(), ALPN).await.map_err(|e| format!("connecting: {e}"))?;
    let answer = admit(&conn, &r.alice.admission(&stranger.id().to_string(), name, &node, now, now + 300)).await?;
    r.ensure(S, "an admission from someone other than its owner is refused", answer["admitted"] == false, answer.to_string())?;
    stranger.close().await;

    // A first contact, from nothing: bind, connect through the relay, the
    // owner's admission, the first answer.
    let t = Instant::now();
    let ep = bind().await.map_err(|e| e.to_string())?;
    let bound = t.elapsed();
    let conn = ep.connect(addr.clone(), ALPN).await.map_err(|e| format!("connecting: {e}"))?;
    let connected = t.elapsed();
    let now = super::client::now_s();
    let admission = r.keys(Owner::Hermes).admission(&ep.id().to_string(), name, &node, now, now + 600);
    let answer = admit(&conn, &admission).await?;
    let admitted = t.elapsed();
    let first = request(&conn, &host, "GET", "/api/status", &[], vec![]).await;
    let answered = t.elapsed();
    r.ensure(
        S,
        "a peer reaches it by its key through the relay, admitted by its owner",
        answer["admitted"] == true && first.as_ref().is_ok_and(|(s, _, _)| *s == 200),
        format!("bound {} ms, connected {} ms, admitted {} ms, first answer {} ms; {}", bound.as_millis(), connected.as_millis(), admitted.as_millis(), answered.as_millis(), path(&conn)),
    )?;

    // Awake: the same request each way, one after another.
    let mut over_iroh = vec![];
    let mut over_url = vec![];
    for _ in 0..AWAKE_SAMPLES {
        let t = Instant::now();
        request(&conn, &host, "GET", "/api/status", &[], vec![]).await?;
        over_iroh.push(t.elapsed());
        let t = Instant::now();
        r.client.send(&host, "GET", "/api/status", &[], vec![]).await?;
        over_url.push(t.elapsed());
    }
    r.record(S, "an awake request", true, format!("by its key: {}; by its URL: {}; {}", spread(&over_iroh), spread(&over_url), path(&conn)));

    // Warm and cold wakes, by its key.
    let mut warm = vec![];
    for _ in 0..WARM_SAMPLES {
        r.slept(name, "warm", "Paused").await?;
        let t = Instant::now();
        let (s, _, _) = request(&conn, &host, "GET", "/api/status", &[], vec![]).await?;
        warm.push(t.elapsed());
        r.ensure(S, "a request by its key wakes a warm Hermes", s == 200, format!("{s}"))?;
    }
    r.record(S, "warm wakes by its key", true, spread(&warm));
    let mut cold = vec![];
    for _ in 0..COLD_SAMPLES {
        r.slept(name, "cold", "Stopped").await?;
        let t = Instant::now();
        let (s, _, _) = request(&conn, &host, "GET", "/api/status", &[], vec![]).await?;
        cold.push(t.elapsed());
        r.ensure(S, "a request by its key wakes a cold Hermes", s < 500, format!("{s}"))?;
    }
    r.record(S, "cold wakes by its key", true, spread(&cold));

    // A chat turn over its socket, by its key: Hermes' own login still
    // gates it here (docs/runtime-seam.md: in a microVM it binds a public
    // address), so the page logs in over the same connection.
    let path_spec = r.args.keys_dir.join("hermes-credentials.json");
    let spec: Value = serde_json::from_str(&std::fs::read_to_string(&path_spec).map_err(|e| format!("{}: {e}", path_spec.display()))?).map_err(|e| e.to_string())?;
    let env = &spec["service"]["env"];
    let login = json!({"provider": "basic", "username": env["HERMES_DASHBOARD_BASIC_AUTH_USERNAME"], "password": env["HERMES_DASHBOARD_BASIC_AUTH_PASSWORD"]});
    let t = Instant::now();
    let (s, headers, _) = request(&conn, &host, "POST", "/auth/password-login", &[("content-type", "application/json")], serde_json::to_vec(&login).map_err(|e| e.to_string())?).await?;
    let token = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|c| c.split(';').next()?.split_once('='))
        .find(|(k, _)| k.ends_with("hermes_session_at"))
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();
    r.ensure(S, "Hermes' own login, by its key", s == 200 && !token.is_empty(), format!("{s} in {} ms", t.elapsed().as_millis()))?;
    let bearer = format!("Bearer {token}");
    let (s, _, body) = request(&conn, &host, "POST", "/api/auth/ws-ticket", &[("authorization", &bearer)], vec![]).await?;
    let ticket = serde_json::from_slice::<Value>(&body).ok().and_then(|v| v["ticket"].as_str().map(str::to_string)).unwrap_or_default();
    r.ensure(S, "a socket ticket, by its key", s == 200 && !ticket.is_empty(), format!("{s}"))?;
    let offered = format!("hermes-gateway-ticket.{ticket}");
    let t = Instant::now();
    let (mut ws, chosen) = websocket(&conn, &host, &["hermes-gateway-v1", &offered]).await?;
    let ready = ws.recv(Duration::from_secs(30)).await?.unwrap_or_default();
    r.ensure(S, "its socket opens over a stream, and the gateway is ready", chosen.as_deref() == Some("hermes-gateway-v1") && ready.contains("gateway.ready"), format!("in {} ms", t.elapsed().as_millis()))?;
    let (created, _) = rpc(&mut ws, 1, "session.create", json!({"title": "sandcastle e2e over iroh"})).await?;
    let live = created["session_id"].as_str().unwrap_or("").to_string();
    let t = Instant::now();
    let (_, events) = rpc(&mut ws, 2, "prompt.submit", json!({"session_id": live, "text": "Reply with exactly: by its key"})).await?;
    let (text, status, first) = turn(&mut ws, &live, events, Duration::from_secs(120)).await?;
    r.ensure(S, "a turn streams by its key", text.to_lowercase().contains("by its key") && status != "error", format!("first words in {} ms, whole in {} ms", first.as_millis(), t.elapsed().as_millis()))?;
    ws.close().await;

    // Quiet under the open connection: it sleeps, and the next request on
    // the connection wakes it.
    let id = r.id_of(name)?;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(90) && !r.host.machine(&id).await?.is_some_and(|m| m.status == "Paused") {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let machine = r.host.machine(&id).await?;
    r.ensure(S, "quiet, it goes warm under an open connection", machine.as_ref().is_some_and(|m| m.status == "Paused"), secs(start.elapsed()))?;
    let t = Instant::now();
    let (s, _, _) = request(&conn, &host, "GET", "/api/status", &[], vec![]).await?;
    r.ensure(S, "and the next request on it wakes it", s == 200, format!("{} ms; {}", t.elapsed().as_millis(), path(&conn)))?;
    ep.close().await;
    Ok(())
}
