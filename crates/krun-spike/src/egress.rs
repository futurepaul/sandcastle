//! Acceptance 5, through the engine: from the guest, with no proxy
//! setting, an HTTPS request to a named host handed to a handler that
//! answers it; a placeholder substituted with its value; with the internet
//! off, a name that is not intercepted does not resolve; a private address
//! refused.
//!
//! The handler is a stand-in for celld's callback route, labeled so in
//! every answer. The substituted value is a labeled test string.

use std::convert::Infallible;
use std::path::PathBuf;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use sandcastle_egress::{Action, Intercept, Placeholder};
use sandcastle_engine::api::Instance;
use sandcastle_engine::StartRequest;
use serde_json::{json, Value};

use crate::layout::Layout;
use crate::node::{start, Ctr, Node};
use crate::{stats, Error};

pub const CURL: &str = "curlimages/curl:8.22.0";
pub const CA_IN_GUEST: &str = "/etc/cloudflare/certs/cloudflare-containers-ca.crt";
pub const MODEL_HOST: &str = "model.example.com";
const SUBSTITUTED_HOST: &str = "httpbin.org";
const PLACEHOLDER: &str = "SC_PLACEHOLDER_TEST_0001";
const TEST_VALUE: &str = "sk-test-not-a-real-secret";
pub const STAND_IN: &str = "the spike's stand-in for celld's callback route";

async fn stand_in(listener: tokio::net::UnixListener) {
    // Unbounded by design: the stand-in serves for the scenario's life.
    loop {
        let Ok((s, _)) = listener.accept().await else { continue };
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let body = json!({
                    "stand_in": STAND_IN,
                    "method": req.method().as_str(),
                    "path": req.uri().path(),
                    "host": h("x-sandcastle-host"),
                    "scheme": h("x-sandcastle-scheme"),
                    "authorization": h("authorization"),
                });
                let mut r = Response::new(Full::new(Bytes::from(body.to_string())));
                r.headers_mut().insert("content-type", "application/json".parse().expect("a header"));
                Ok::<_, Infallible>(r)
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
        });
    }
}

/// The stand-in handler on a unix socket, on a runtime of its own.
pub struct StandIn {
    _rt: tokio::runtime::Runtime,
    pub socket: PathBuf,
}

impl StandIn {
    pub fn new(layout: &Layout) -> Result<StandIn, Error> {
        std::fs::create_dir_all(layout.tmp()).map_err(Error::io("tmp"))?;
        let socket = layout.tmp().join("handler.sock");
        let _ = std::fs::remove_file(&socket);
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().map_err(Error::io("a runtime"))?;
        let listener = {
            let _guard = rt.enter();
            tokio::net::UnixListener::bind(&socket).map_err(Error::io("the stand-in's socket"))?
        };
        rt.spawn(stand_in(listener));
        Ok(StandIn { _rt: rt, socket })
    }

    pub fn handler(&self) -> String {
        format!("unix:{}", self.socket.display())
    }
}

pub fn intercepts() -> Vec<Intercept> {
    vec![
        Intercept::https(MODEL_HOST, Action::Handler),
        Intercept::https("openrouter.ai", Action::Handler),
        Intercept::https("*.openrouter.ai", Action::Handler),
        Intercept::https(SUBSTITUTED_HOST, Action::Substitute { placeholders: vec![Placeholder { placeholder: PLACEHOLDER.into(), value: TEST_VALUE.into() }] }),
    ]
}

fn curl_start(internet: bool, handler: &str) -> StartRequest {
    let mut s = start(CURL, crate::scenarios::SLEEP_FOREVER);
    s.enable_internet = internet;
    s.intercepts = intercepts();
    s.handler = Some(handler.into());
    s
}

pub fn scenario(layout: &Layout, node: &Node) -> Result<Value, Error> {
    let node_ip = crate::layout::node_ip()?;
    let stand_in = StandIn::new(layout)?;
    let curl = format!("curl -sS --cacert {CA_IN_GUEST} -m 20");

    // The internet on: intercepted, substituted, spliced, and refused.
    let on = node.start("egress-on", &curl_start(true, &stand_in.handler()))?;
    let (handled, _) = on.sh(&format!("{curl} https://{MODEL_HOST}/v1/chat/completions -H 'Authorization: Bearer {PLACEHOLDER}' -d '{{}}'"))?;
    let (substituted, _) = on.sh(&format!("{curl} https://{SUBSTITUTED_HOST}/headers -H 'Authorization: Bearer {PLACEHOLDER}'"))?;
    let (spliced, _) = on.sh("curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.com/")?;
    let (private, _) = on.sh("curl -sS -m 5 http://10.0.0.1/; echo rc=$?; curl -sS -m 5 http://169.254.169.254/latest/meta-data/; echo rc=$?")?;
    let (ssh, https) = (std::net::SocketAddr::new(node_ip, 22), std::net::SocketAddr::new(node_ip, 443));
    let (node_refused, _) = on.sh(&format!("curl -sS -m 5 http://{ssh}/; echo rc=$?; curl -sS -m 5 http://{https}/; echo rc=$?"))?;
    // The handler's round trip on `lite` (Cloudflare's default, 1/16 vCPU:
    // a TLS handshake can spend its 6.25 ms a period and wait out the
    // rest, which `cpu.stat` shows), and on `standard-1` (1/2 vCPU), where
    // the path alone is timed.
    let (periods, usec) = on.throttled();
    let lite_ms = time_handler(&on, &curl)?;
    let (periods_after, usec_after) = on.throttled();
    on.destroy(None)?;
    let mut s1 = curl_start(true, &stand_in.handler());
    s1.instance = Some(Instance::Named("standard-1".into()));
    let bigger = node.start("egress-standard-1", &s1)?;
    let standard_ms = time_handler(&bigger, &curl)?;
    let (periods_s1, _) = bigger.throttled();
    bigger.destroy(None)?;

    // The internet off: only intercepted names resolve.
    let off = node.start("egress-off", &curl_start(false, &stand_in.handler()))?;
    let (lookup_public, lookup_public_rc) = off.sh("nslookup example.com")?;
    let (lookup_model, _) = off.sh(&format!("nslookup {MODEL_HOST}"))?;
    let (handled_off, _) = off.sh(&format!("{curl} https://{MODEL_HOST}/v1/chat/completions -d '{{}}'"))?;
    let (direct_ip, _) = off.sh("curl -sS -m 5 -k https://1.1.1.1/; echo rc=$?")?;
    off.destroy(None)?;

    let checks = json!({
        "handler_answered": handled.contains(STAND_IN) && handled.contains(MODEL_HOST),
        "placeholder_substituted": substituted.contains(TEST_VALUE) && !substituted.contains(PLACEHOLDER),
        "spliced_with_real_tls": spliced.trim() == "200",
        "private_refused": private.matches("rc=").count() == 2 && !private.contains("rc=0"),
        "node_refused": !node_refused.contains("rc=0"),
        "off_public_name_unresolved": lookup_public_rc != Some(0) || lookup_public.contains("NXDOMAIN") || lookup_public.contains("can't find"),
        "off_intercepted_name_resolved": lookup_model.contains("198.18."),
        "off_handler_answered": handled_off.contains(STAND_IN),
        "off_direct_ip_refused": !direct_ip.contains("rc=0"),
    });
    let pass = checks.as_object().expect("an object").values().all(|v| v == true);
    Ok(json!({
        "pass": pass,
        "checks": checks,
        "handler_request_ms_in_guest": {
            "lite": stats(&lite_ms),
            "lite_throttled": {"periods": periods_after - periods, "ms": (usec_after - usec) / 1000},
            "standard_1": stats(&standard_ms),
            "standard_1_throttled_periods": periods_s1,
        },
        "handled": handled.trim(),
        "substituted": substituted.chars().take(600).collect::<String>(),
        "private": private,
        "node": node_refused,
        "off_lookup_public": lookup_public,
        "off_lookup_model": lookup_model,
        "off_direct_ip": direct_ip,
    }))
}

/// Five requests to the handler from inside, curl's own clock.
fn time_handler(c: &Ctr<'_>, curl: &str) -> Result<Vec<f64>, Error> {
    let mut ms = vec![];
    for _ in 0..5 {
        let (t, _) = c.sh(&format!("{curl} -o /dev/null -w '%{{time_total}}' https://{MODEL_HOST}/v1/models"))?;
        ms.push(t.trim().parse::<f64>().map_err(|_| Error::msg(format!("curl's time: {t}")))? * 1000.0);
    }
    Ok(ms)
}
