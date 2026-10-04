//! Intercepts, handed to the platform (docs/node.md, Intercepts). Every
//! container this node starts names this node's handler socket to the
//! engine. The engine's egress proxy sends each intercepted request here,
//! with `x-sandcastle-container`, `-intercept`, `-host` and `-scheme` set
//! (overwriting whatever the guest sent). The node reads the request whole
//! (at most `BODY_BYTES_MAX`), signs it (`auth::Egress`), and sends it to
//! the platform's `/api/nodes/egress` with its path in `x-sandcastle-path`.
//! The platform's answer streams back to the guest.
//!
//! A WebSocket's upgrade has no body: it is signed over the empty one, and
//! goes on with its `connection` and `upgrade` (the only hop headers that
//! pass). On the platform's 101 the node answers 101 with the platform's
//! headers, and joins the two connections both ways; any other answer
//! passes back as one.

use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response};

use crate::auth;
use crate::http::{self, Body};
use crate::Node;

/// An intercepted request's body, at most (the engine's own bound).
pub const BODY_BYTES_MAX: usize = 32 << 20;
/// The platform's route for intercepts.
pub const ROUTE: &str = "/api/nodes/egress";

async fn forward(node: Arc<Node>, mut req: Request<Incoming>) -> Response<Body> {
    let websocket = http::websocket(req.headers());
    let engine_side = websocket.then(|| hyper::upgrade::on(&mut req));
    let h = req.headers();
    let get = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).map(str::to_string);
    let (Some(container), Some(intercept), Some(host), Some(scheme)) =
        (get("x-sandcastle-container"), get("x-sandcastle-intercept"), get("x-sandcastle-host"), get("x-sandcastle-scheme"))
    else {
        return http::error(400, "invalid", "an intercept without the engine's x-sandcastle headers");
    };
    let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let method = req.method().clone();
    let mut headers = req.headers().clone();
    let body = if websocket {
        hyper::body::Bytes::new()
    } else {
        match Limited::new(req.into_body(), BODY_BYTES_MAX).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return http::error(413, "invalid", &format!("an intercepted request's body is at most {BODY_BYTES_MAX} bytes")),
        }
    };
    let t = auth::now_s();
    let signed = auth::Egress { method: method.as_str(), container: &container, intercept: &intercept, scheme: &scheme, host: &host, path: &path };
    let signature = node.secret.header(t, &signed.string(t, &auth::sha256_hex(&body)));
    for k in http::HOP {
        if !(websocket && (k == "connection" || k == "upgrade")) {
            headers.remove(k);
        }
    }
    headers.remove(auth::HEADER);
    let mut out = Request::builder().method(method).uri(ROUTE).body(http::full(body)).expect("a request");
    *out.headers_mut() = headers;
    let oh = out.headers_mut();
    oh.insert("host", node.platform.authority().parse().expect("a host"));
    oh.insert("x-sandcastle-path", path.parse().unwrap_or_else(|_| "/".parse().expect("a header")));
    oh.insert(auth::HEADER, signature.parse().expect("a header"));
    match node.platform.send(out).await {
        Ok(mut resp) => {
            if let (hyper::StatusCode::SWITCHING_PROTOCOLS, Some(engine_side)) = (resp.status(), engine_side) {
                tokio::spawn(http::splice(engine_side, hyper::upgrade::on(&mut resp)));
            }
            resp.map(http::streamed)
        }
        Err(e) => http::error(502, "upstream", &e),
    }
}

/// Serves the handler socket until the process ends.
pub async fn serve(node: Arc<Node>, listener: tokio::net::UnixListener) {
    // Unbounded by design: one task per connection, for the node's life.
    loop {
        let Ok((s, _)) = listener.accept().await else { continue };
        let node = node.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let node = node.clone();
                async move { Ok::<_, Infallible>(forward(node, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).with_upgrades().await;
        });
    }
}
