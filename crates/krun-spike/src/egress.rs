//! Acceptance 5: from the guest, with no proxy setting, an HTTPS request
//! to a named host handed to a handler that answers it; a placeholder
//! substituted with its value; with the internet off, a name that is not
//! intercepted does not resolve; a private address refused.
//!
//! The handler here is a stand-in for celld's callback route, labeled so
//! in every answer it gives. The substituted value is a labeled test
//! string, not a secret.

use std::convert::Infallible;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use sandcastle_egress::ca::Ca;
use sandcastle_egress::{Action, Egress, Intercept, Placeholder, Policy};
use sandcastle_vm::Net;
use sandcastle_wire::egress::{EGRESS_SOCK, GATEWAY_ADDR, GUEST_ADDR, MTU, PREFIX};
use sandcastle_wire::{GuestNet, Process, Start};
use serde_json::{json, Value};

use crate::image::{self, Image};
use crate::launch::{self, Jail, Running, Spec};
use crate::layout::Layout;
use crate::{stats, Error};

pub const CURL: &str = "curlimages/curl:8.22.0";
const CA_IN_GUEST: &str = "/etc/cloudflare/certs/cloudflare-containers-ca.crt";
const MODEL_HOST: &str = "model.example.com";
const SUBSTITUTED_HOST: &str = "httpbin.org";
const PLACEHOLDER: &str = "SC_PLACEHOLDER_TEST_0001";
const TEST_VALUE: &str = "sk-test-not-a-real-secret";

/// Every address the node answers on: the guest must reach none of them.
pub fn node_addrs() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a list we walk and then free.
    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut p = ifap;
        // Bounded by the list's length.
        while !p.is_null() {
            let a = (*p).ifa_addr;
            if !a.is_null() {
                match (*a).sa_family as libc::c_int {
                    libc::AF_INET => {
                        let s = &*(a as *const libc::sockaddr_in);
                        out.push(IpAddr::from(u32::from_be(s.sin_addr.s_addr).to_be_bytes()));
                    }
                    libc::AF_INET6 => {
                        let s = &*(a as *const libc::sockaddr_in6);
                        out.push(IpAddr::from(s.sin6_addr.s6_addr));
                    }
                    _ => {}
                }
            }
            p = (*p).ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

async fn stand_in(listener: tokio::net::UnixListener) {
    // Unbounded by design: the stand-in serves for the scenario's life.
    loop {
        let Ok((s, _)) = listener.accept().await else { continue };
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let body = json!({
                    "stand_in": "the spike's stand-in for celld's callback route",
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

pub struct World {
    pub rt: tokio::runtime::Runtime,
    pub ca: Arc<Ca>,
    pub handler: std::path::PathBuf,
    pub node: Vec<IpAddr>,
}

impl World {
    /// A CA, the stand-in handler on a unix socket, and the runtime both
    /// run on.
    pub fn new(layout: &Layout) -> Result<World, Error> {
        std::fs::create_dir_all(layout.tmp()).map_err(Error::io("tmp"))?;
        let handler = layout.tmp().join("handler.sock");
        let _ = std::fs::remove_file(&handler);
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().map_err(Error::io("a runtime"))?;
        let listener = {
            let _guard = rt.enter();
            tokio::net::UnixListener::bind(&handler).map_err(Error::io("the stand-in's socket"))?
        };
        rt.spawn(stand_in(listener));
        let ca = Arc::new(Ca::generate("sandcastle spike CA").map_err(|e| Error::msg(e.to_string()))?);
        Ok(World { rt, ca, handler, node: node_addrs() })
    }
}

pub fn policy(internet: bool) -> Policy {
    Policy {
        internet,
        allow: vec![],
        deny: vec![],
        intercept: vec![
            Intercept { host: MODEL_HOST.into(), action: Action::Handler },
            Intercept { host: "openrouter.ai".into(), action: Action::Handler },
            Intercept { host: "*.openrouter.ai".into(), action: Action::Handler },
            Intercept {
                host: SUBSTITUTED_HOST.into(),
                action: Action::Substitute { placeholders: vec![Placeholder { placeholder: PLACEHOLDER.into(), value: TEST_VALUE.into() }] },
            },
        ],
    }
}

/// What a networked VM runs, beyond its image's defaults.
pub struct NetVm<'a> {
    pub id: &'a str,
    pub internet: bool,
    pub jail: Jail,
    pub slot: u32,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    /// The data disk and where the guest mounts it.
    pub data: Option<(std::path::PathBuf, String)>,
}

pub fn net_vm(layout: &Layout, w: &World, img: &Image, v: NetVm<'_>) -> Result<(Running, Arc<Egress>), Error> {
    let rules = policy(v.internet).compile(&w.node).map_err(|e| Error::msg(e.to_string()))?;
    let egress = Arc::new(Egress::new(rules, w.ca.clone(), w.handler.clone()));
    let (eg, handle) = (egress.clone(), w.rt.handle().clone());
    let before = Box::new(move |run_dir: &Path| -> Result<(), Error> {
        let sock = run_dir.join(EGRESS_SOCK);
        let listener = {
            let _guard = handle.enter();
            tokio::net::UnixListener::bind(&sock).map_err(Error::io("binding the egress socket"))?
        };
        // The VM uid connects to it from inside its jail.
        std::fs::set_permissions(&sock, std::os::unix::fs::PermissionsExt::from_mode(0o777)).map_err(Error::io("the egress socket's mode"))?;
        handle.spawn(eg.serve(listener));
        Ok(())
    });
    let argv: Vec<&str> = v.argv.iter().map(String::as_str).collect();
    let mut start = crate::scenarios::run_start(img, v.id, &argv, v.data.is_some());
    if let Start::Run { ca_pem, net, entrypoint, data_path, .. } = &mut start {
        *ca_pem = Some(w.ca.cert_pem().to_string());
        *net = Some(GuestNet {
            address: format!("{GUEST_ADDR}/{PREFIX}"),
            gateway: GATEWAY_ADDR.to_string(),
            dns: GATEWAY_ADDR.to_string(),
            mtu: MTU,
        });
        entrypoint.env.extend(v.env);
        *data_path = v.data.as_ref().map(|(_, p)| p.clone());
    }
    let running = launch::start(
        layout,
        Spec {
            id: v.id.into(),
            vcpus: v.vcpus,
            memory_mib: v.memory_mib,
            image: Some(img.root.clone()),
            target: None,
            scratch_bytes: Some(16 << 30),
            data: v.data.map(|(d, _)| d),
            net: Net::Tap { name: "tap0".into(), mac: [0x02, 0x53, 0x43, 0, 0, v.slot as u8 + 1] },
            start,
            jail: v.jail,
            slot: v.slot,
            probe: None,
            before: Some(before),
        },
    )?;
    Ok((running, egress))
}

fn vm(layout: &Layout, w: &World, img: &Image, id: &str, internet: bool, jail: Jail, slot: u32) -> Result<(Running, Arc<Egress>), Error> {
    let argv = ["/bin/sh", "-c", "while :; do sleep 3600; done"].iter().map(|s| s.to_string()).collect();
    net_vm(layout, w, img, NetVm { id, internet, jail, slot, vcpus: 1, memory_mib: 512, argv, env: vec![], data: None })
}

fn sh(vm: &Running, script: &str) -> Result<(String, Option<i32>), Error> {
    let out = vm
        .vm
        .exec(Process { argv: vec!["/bin/sh".into(), "-c".into(), script.into()], ..Process::default() }, None)
        .map_err(|e| Error::msg(format!("exec: {e}")))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((text, out.code))
}

pub fn scenario(layout: &Layout, jail: Jail) -> Result<Value, Error> {
    let (img, _) = image::ensure(layout, CURL, jail)?;
    let w = World::new(layout)?;

    // The internet on: intercepted, substituted, spliced, and refused.
    let (mut on, on_egress) = vm(layout, &w, &img, "egress-on", true, jail, 0)?;
    on.wait_for("ready", Duration::from_secs(60))?;
    let curl = format!("curl -sS --cacert {CA_IN_GUEST} -m 20");
    let (handled, _) = sh(&on, &format!("{curl} https://{MODEL_HOST}/v1/chat/completions -H 'Authorization: Bearer {PLACEHOLDER}' -d '{{}}'"))?;
    let (substituted, _) = sh(&on, &format!("{curl} https://{SUBSTITUTED_HOST}/headers -H 'Authorization: Bearer {PLACEHOLDER}'"))?;
    let (spliced, _) = sh(&on, "curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.com/")?;
    let (private, private_rc) = sh(&on, "curl -sS -m 5 http://10.0.0.1/; echo rc=$?; curl -sS -m 5 http://169.254.169.254/latest/meta-data/; echo rc=$?")?;
    let node_ip = w.node.iter().find(|a| sandcastle_egress::rules::is_public(**a)).map(|a| a.to_string()).unwrap_or_default();
    let (node, _) = sh(&on, &format!("curl -sS -m 5 http://{node_ip}:22/; echo rc=$?; curl -sS -m 5 http://{node_ip}:443/; echo rc=$?"))?;
    let mut handler_ms = vec![];
    for _ in 0..5 {
        let (t, _) = sh(&on, &format!("{curl} -o /dev/null -w '%{{time_total}}' https://{MODEL_HOST}/v1/models"))?;
        if let Ok(s) = t.trim().parse::<f64>() {
            handler_ms.push(s * 1000.0);
        }
    }
    let on_decisions = on_egress.decisions();
    on.kill()?;
    launch::remove_run_dir(layout, "egress-on");

    // The internet off: only intercepted names resolve.
    let (mut off, off_egress) = vm(layout, &w, &img, "egress-off", false, jail, 1)?;
    off.wait_for("ready", Duration::from_secs(60))?;
    let (lookup_public, lookup_public_rc) = sh(&off, "nslookup example.com")?;
    let (lookup_model, _) = sh(&off, &format!("nslookup {MODEL_HOST}"))?;
    let (handled_off, _) = sh(&off, &format!("{curl} https://{MODEL_HOST}/v1/chat/completions -d '{{}}'"))?;
    let (direct_ip, _) = sh(&off, "curl -sS -m 5 -k https://1.1.1.1/; echo rc=$?")?;
    let off_decisions = off_egress.decisions();
    off.kill()?;
    launch::remove_run_dir(layout, "egress-off");

    drop(w);
    let checks = json!({
        "handler_answered": handled.contains("stand-in for celld's callback route") && handled.contains(MODEL_HOST),
        "placeholder_substituted": substituted.contains(TEST_VALUE) && !substituted.contains(PLACEHOLDER),
        "spliced_with_real_tls": spliced.trim() == "200",
        "private_refused": private.matches("rc=").count() == 2 && !private.contains("rc=0") && private_rc == Some(0),
        "node_refused": !node.contains("rc=0"),
        "off_public_name_unresolved": lookup_public_rc != Some(0) || lookup_public.contains("NXDOMAIN") || lookup_public.contains("can't find"),
        "off_intercepted_name_resolved": lookup_model.contains("198.18."),
        "off_handler_answered": handled_off.contains("stand-in for celld's callback route"),
        "off_direct_ip_refused": !direct_ip.contains("rc=0"),
    });
    let pass = checks.as_object().expect("an object").values().all(|v| v == true);
    Ok(json!({
        "pass": pass,
        "checks": checks,
        "handler_request_ms_in_guest": if handler_ms.is_empty() { Value::Null } else { stats(&handler_ms) },
        "handled": handled.trim(),
        "substituted": substituted.chars().take(600).collect::<String>(),
        "private": private,
        "node": node,
        "off_lookup_public": lookup_public,
        "off_lookup_model": lookup_model,
        "off_direct_ip": direct_ip,
        "decisions_on": on_decisions,
        "decisions_off": off_decisions,
    }))
}
