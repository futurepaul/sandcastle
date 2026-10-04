//! A container's intercepts, as the double gives them. An intercept of an
//! exact host on 80 (http) or 443 (https) sends that host to 127.0.0.1 in
//! the container's `/etc/hosts`, where the relay (`sandcastle-docker-relay`)
//! listens and joins each connection to the container's `http.sock` or
//! `https.sock`, which this serves. HTTPS is terminated with the double's
//! CA (`sandcastle_egress::ca`), for the name the guest's TLS asked for.
//! Each request then goes to the container's handler with the headers the
//! engine's egress proxy sets, both bodies streamed, never held. A
//! WebSocket's upgrade goes the same way, its upgrade headers intact; on
//! the handler's 101 the guest gets the 101, and the two connections are
//! joined both ways until each side is done.

use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::HeaderValue;
use hyper::{Request, Response};
use sandcastle_egress::rules::{parse_target, Action, Glob, Intercept, Scheme, Target};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixListener;

use crate::Shared;

/// A guest's TLS handshake, at most.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);

type Body = BoxBody<Bytes, hyper::Error>;

fn refused(status: u16, message: &str) -> Response<Body> {
    let body = serde_json::to_vec(&serde_json::json!({ "error": message, "kind": "upstream" })).expect("serializes");
    let mut r = Response::new(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed());
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("a status");
    r.headers_mut().insert("content-type", HeaderValue::from_static("application/json"));
    r
}

/// The host an intercept sends to the relay; why the double cannot route
/// it, otherwise. The double routes exact hosts on 80 and 443 only: the
/// guest reaches them by name through `/etc/hosts`, which holds no globs.
pub fn routed_host(i: &Intercept) -> Result<String, String> {
    if i.action != Action::Handler {
        return Err(format!("{}: the double hands requests to the handler only; it substitutes nothing", i.target));
    }
    let only = || format!("{}: the double routes exact hosts on 80 (http) and 443 (https) only", i.target);
    match parse_target(i.scheme, &i.target) {
        Ok((Target::Host(_), port)) if port == i.scheme.port() && !i.target.starts_with("*.") => {
            let host = match i.scheme {
                Scheme::Https => i.target.strip_suffix(":443").unwrap_or(&i.target),
                Scheme::Http => &i.target,
            };
            Ok(host.trim_end_matches('.').to_ascii_lowercase())
        }
        Ok(_) => Err(only()),
        Err(e) => Err(e.to_string()),
    }
}

/// The index of the intercept `scheme://host:port` falls under, as the
/// egress proxy decides it (and the fake engine), for intercepts that hand
/// requests over.
pub fn intercept_of(intercepts: &[Intercept], scheme: Scheme, host: &str, port: u16) -> Option<usize> {
    intercepts.iter().position(|i| {
        i.scheme == scheme
            && i.action == Action::Handler
            && match parse_target(i.scheme, &i.target) {
                Ok((Target::Host(g), p)) => p == port && g.matches(host),
                Ok((Target::Any, p)) => p == port,
                _ => false,
            }
    })
}

/// A request's `Host`, without its port: a name, never an address.
pub fn host_of(header: Option<&HeaderValue>) -> Option<String> {
    let h = header?.to_str().ok()?;
    let name = match h.rsplit_once(':') {
        Some((n, p)) if p.bytes().all(|b| b.is_ascii_digit()) => n,
        _ => h,
    };
    exact(name)
}

/// `name` as an exact host the rules could name; nothing for a glob, an
/// address, or junk.
fn exact(name: &str) -> Option<String> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name.starts_with('*') || name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Glob::parse(&name).map(|_| name)
}

/// Serves one container's `http.sock` (`tls` false) or `https.sock`.
pub(crate) async fn serve(shared: Arc<Shared>, name: String, run: u64, listener: UnixListener, tls: bool) {
    // Unbounded by design: the container's life (its end aborts this);
    // the connections at once are bounded by the relay's.
    loop {
        let Ok((conn, _)) = listener.accept().await else { continue };
        let (shared, name) = (shared.clone(), name.clone());
        tokio::spawn(async move {
            if !tls {
                return http(shared, name, run, conn, Scheme::Http, None).await;
            }
            let accepting = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), conn);
            let start = match tokio::time::timeout(HANDSHAKE_WAIT, accepting).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return crate::note(&name, format!("a guest's TLS hello: {e}")),
                Err(_) => return crate::note(&name, "a guest's TLS hello: none in time".into()),
            };
            let Some(sni) = start.client_hello().server_name().and_then(exact) else {
                return crate::note(&name, "a guest's TLS hello without a host's name: refused".into());
            };
            let config = match shared.ca.server_config(&sni) {
                Ok(c) => c,
                Err(e) => return crate::note(&name, format!("a certificate for {sni}: {e}")),
            };
            let stream = match tokio::time::timeout(HANDSHAKE_WAIT, start.into_stream(config)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return crate::note(&name, format!("a guest's TLS handshake for {sni}: {e}")),
                Err(_) => return crate::note(&name, format!("a guest's TLS handshake for {sni}: not done in time")),
            };
            http(shared, name, run, stream, Scheme::Https, Some(sni)).await
        });
    }
}

async fn http<S>(shared: Arc<Shared>, name: String, run: u64, io: S, scheme: Scheme, sni: Option<String>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |req| {
        let (shared, name, sni) = (shared.clone(), name.clone(), sni.clone());
        async move { Ok::<_, Infallible>(forward(shared, &name, run, req, scheme, sni).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(io), svc).with_upgrades().await;
}

/// Whether a request asks to become a WebSocket.
pub fn websocket(h: &hyper::HeaderMap) -> bool {
    let has = |k: &str, token: &str| h.get_all(k).iter().filter_map(|v| v.to_str().ok()).any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)));
    has("connection", "upgrade") && has("upgrade", "websocket")
}

/// Joins the guest's upgraded connection to the handler's, both ways.
async fn splice(guest: hyper::upgrade::OnUpgrade, handler: hyper::upgrade::OnUpgrade) {
    if let (Ok(g), Ok(h)) = (guest.await, handler.await) {
        let mut g = hyper_util::rt::TokioIo::new(g);
        let mut h = hyper_util::rt::TokioIo::new(h);
        let _ = tokio::io::copy_bidirectional(&mut g, &mut h).await;
    }
}

/// One request the guest made, to its handler: an HTTPS one by the name
/// its TLS asked for, a plain one by its `Host`.
async fn forward(shared: Arc<Shared>, name: &str, run: u64, mut req: Request<Incoming>, scheme: Scheme, sni: Option<String>) -> Response<Body> {
    let Some(host) = sni.or_else(|| host_of(req.headers().get("host"))) else { return refused(502, "a request without a host's name") };
    let port = scheme.port();
    let label = if scheme == Scheme::Https { "https" } else { "http" };
    let found: Option<(usize, Option<PathBuf>)> = {
        let s = shared.state.lock().expect("state");
        let Some(c) = s.containers.get(name).filter(|c| c.run == run && c.info.running) else { return refused(502, &format!("no container {name} running")) };
        intercept_of(&c.intercepts, scheme, &host, port).map(|i| (i, c.handler.clone()))
    };
    let (index, handler) = match found {
        Some((i, Some(h))) => (i, h),
        Some((_, None)) => return refused(502, "an intercept without a handler"),
        None => {
            crate::note(name, format!("guest {} {label}://{host}{}: refused: not intercepted, and the double routes nothing else", req.method(), req.uri()));
            return refused(502, &format!("{label}://{host}: not intercepted, and the Docker double routes nothing else"));
        }
    };
    let guest_side = websocket(req.headers()).then(|| hyper::upgrade::on(&mut req));
    // what the egress proxy sets, over anything the guest sent
    let h = req.headers_mut();
    h.insert("x-sandcastle-host", HeaderValue::from_str(&host).expect("a checked host"));
    h.insert("x-sandcastle-scheme", HeaderValue::from_static(label));
    h.insert("x-sandcastle-container", HeaderValue::from_str(name).expect("a checked name"));
    h.insert("x-sandcastle-intercept", HeaderValue::from(index));
    let method = req.method().clone();
    let path = req.uri().clone();
    let answered = async {
        let s = tokio::net::UnixStream::connect(&handler).await.map_err(|e| format!("the handler at {}: {e}", handler.display()))?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.map_err(|e| e.to_string())?;
        tokio::spawn(conn.with_upgrades());
        send.send_request(req).await.map_err(|e| e.to_string())
    };
    match answered.await {
        Ok(mut resp) => {
            let status = resp.status();
            crate::note(name, format!("guest {method} {label}://{host}{path}: intercept {index} answered {}", status.as_u16()));
            if let (hyper::StatusCode::SWITCHING_PROTOCOLS, Some(guest_side)) = (status, guest_side) {
                tokio::spawn(splice(guest_side, hyper::upgrade::on(&mut resp)));
            }
            resp.map(|b| b.boxed())
        }
        Err(e) => {
            crate::note(name, format!("guest {method} {label}://{host}{path}: the handler failed: {e}"));
            refused(502, &format!("the handler: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler(scheme: Scheme, target: &str) -> Intercept {
        Intercept { scheme, target: target.into(), action: Action::Handler }
    }

    // Goal: exact hosts on 80 and 443 route; a glob, `*`, an address, a
    // range, another port, and a substitute are each refused, saying why.
    #[test]
    fn what_the_double_routes() {
        assert_eq!(routed_host(&handler(Scheme::Http, "api.fragment.internal")), Ok("api.fragment.internal".into()));
        assert_eq!(routed_host(&handler(Scheme::Https, "Model.Example.com.")), Ok("model.example.com".into()));
        assert_eq!(routed_host(&handler(Scheme::Https, "model.example.com:443")), Ok("model.example.com".into()));
        for (scheme, target) in [(Scheme::Http, "*.example.com"), (Scheme::Http, "*"), (Scheme::Https, "*"), (Scheme::Https, "x.example.com:8443"), (Scheme::Http, "10.0.0.1:8080"), (Scheme::Http, "10.0.0.0/8")] {
            let e = routed_host(&handler(scheme, target)).unwrap_err();
            assert!(e.contains("exact hosts on 80 (http) and 443 (https) only"), "{target}: {e}");
        }
        assert!(routed_host(&handler(Scheme::Http, "not a host")).is_err());
        let sub = Intercept::http("api.example.com", Action::Substitute { placeholders: vec![] });
        assert!(routed_host(&sub).unwrap_err().contains("handler only"));
    }

    // Goal: a request's host finds its intercept's index in the list, by
    // scheme; a substitute never hands a request over.
    #[test]
    fn routing_a_requests_host() {
        let list = vec![
            Intercept::http("api.example.com", Action::Substitute { placeholders: vec![] }),
            handler(Scheme::Http, "api.fragment.internal"),
            handler(Scheme::Https, "api.fragment.internal"),
            handler(Scheme::Http, "model.fragment.internal"),
        ];
        assert_eq!(intercept_of(&list, Scheme::Http, "api.fragment.internal", 80), Some(1));
        assert_eq!(intercept_of(&list, Scheme::Https, "API.fragment.internal", 443), Some(2));
        assert_eq!(intercept_of(&list, Scheme::Http, "model.fragment.internal", 80), Some(3));
        assert_eq!(intercept_of(&list, Scheme::Https, "model.fragment.internal", 443), None);
        assert_eq!(intercept_of(&list, Scheme::Http, "api.example.com", 80), None);
        assert_eq!(intercept_of(&list, Scheme::Http, "elsewhere.example", 80), None);
        assert_eq!(intercept_of(&[], Scheme::Http, "api.fragment.internal", 80), None);
    }

    #[test]
    fn websocket_upgrades() {
        let h = |pairs: &[(&str, &str)]| {
            let mut m = hyper::HeaderMap::new();
            for (k, v) in pairs {
                m.append(hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
            }
            websocket(&m)
        };
        assert!(h(&[("connection", "Upgrade"), ("upgrade", "websocket")]));
        assert!(h(&[("connection", "keep-alive, Upgrade"), ("upgrade", "WebSocket")]));
        assert!(!h(&[("upgrade", "websocket")]));
        assert!(!h(&[("connection", "upgrade"), ("upgrade", "h2c")]));
    }

    #[test]
    fn hosts_of_requests() {
        let h = |v: &str| host_of(Some(&HeaderValue::from_str(v).unwrap()));
        assert_eq!(h("api.fragment.internal"), Some("api.fragment.internal".into()));
        assert_eq!(h("API.fragment.internal:80"), Some("api.fragment.internal".into()));
        assert_eq!(h("api.fragment.internal."), Some("api.fragment.internal".into()));
        assert_eq!(h("127.0.0.1"), None);
        assert_eq!(h("[::1]:80"), None);
        assert_eq!(h("*.example.com"), None);
        assert_eq!(h(""), None);
        assert_eq!(host_of(None), None);
    }
}
