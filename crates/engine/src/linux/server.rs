//! The engine's API on its unix socket: HTTP/1.1 and JSON, one route per
//! Cloudflare call. Bodies are bounded; every answer that is not a success
//! is an `ErrorBody` with the HTTP status its kind maps to.

use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::engine::Engine;
use crate::api::{ApiError, DestroyRequest, ErrorBody, ExecRequest, InterceptsRequest, SignalRequest, SnapshotRequest, StartRequest};

/// A request body, as read.
pub const BODY_BYTES_MAX: usize = 1 << 20;

fn json<T: Serialize>(status: u16, v: &T) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(serde_json::to_vec(v).expect("serializes"))));
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("a status");
    r.headers_mut().insert("content-type", "application/json".parse().expect("a header"));
    r
}

fn error(e: ApiError) -> Response<Full<Bytes>> {
    json(e.status(), &ErrorBody { error: e.to_string(), kind: e.kind().into() })
}

fn empty(status: u16) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::new()));
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("a status");
    r
}

async fn body<T: DeserializeOwned>(req: Request<Incoming>) -> Result<T, ApiError> {
    let bytes = Limited::new(req.into_body(), BODY_BYTES_MAX)
        .collect()
        .await
        .map_err(|_| ApiError::Invalid(format!("a body of at most {BODY_BYTES_MAX} bytes")))?
        .to_bytes();
    // serde's message names a position, not the input.
    serde_json::from_slice(&bytes).map_err(|e| ApiError::Invalid(format!("the body: {e}")))
}

/// A large body (an image) streamed to a file under the engine's tmp,
/// bounded by `load::IMAGE_BYTES_MAX`.
async fn save_body(engine: &Engine, req: Request<Incoming>) -> Result<std::path::PathBuf, ApiError> {
    use tokio::io::AsyncWriteExt;
    let dir = engine.config().tmp();
    let path = dir.join(format!("upload-{}-{}.tar", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)));
    let mut f = tokio::fs::File::create(&path).await.map_err(|e| ApiError::Internal(format!("an upload: {e}")))?;
    let mut body = req.into_body();
    let mut total = 0u64;
    // Bounded by IMAGE_BYTES_MAX.
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| ApiError::Invalid(format!("the upload: {e}")))?;
        if let Ok(data) = frame.into_data() {
            total += data.len() as u64;
            if total > crate::load::IMAGE_BYTES_MAX {
                let _ = tokio::fs::remove_file(&path).await;
                return Err(ApiError::Invalid("the image passes its size limit".into()));
            }
            f.write_all(&data).await.map_err(|e| ApiError::Internal(format!("an upload: {e}")))?;
        }
    }
    f.flush().await.map_err(|e| ApiError::Internal(format!("an upload: {e}")))?;
    Ok(path)
}

/// `exec`'s answer: the switch to its framed stream.
fn switching() -> Response<Full<Bytes>> {
    let mut r = empty(101);
    r.headers_mut().insert("connection", "Upgrade".parse().expect("a header"));
    r.headers_mut().insert("upgrade", crate::exec_stream::UPGRADE.parse().expect("a header"));
    r
}

pub async fn route(engine: Arc<Engine>, mut req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let path: Vec<String> = req.uri().path().trim_matches('/').split('/').map(str::to_string).collect();
    let query = req.uri().query().unwrap_or("").to_string();
    let p: Vec<&str> = path.iter().map(String::as_str).collect();
    let method = req.method().clone();
    let r = match (&method, p.as_slice()) {
        (&Method::GET, ["v1", "health"]) => Ok(json(200, &engine.health())),
        (&Method::GET, ["v1", "containers"]) => Ok(json(200, &engine.list())),
        (&Method::GET, ["v1", "containers", name]) => engine.inspect(name).map(|i| json(200, &i)),
        (&Method::POST, ["v1", "containers", name, "start"]) => {
            let name = name.to_string();
            match body::<StartRequest>(req).await {
                Ok(s) => engine.start_timed(&name, s, query.split('&').any(|q| q == "wait=ready")).await.map(|(i, t)| {
                    let mut v = serde_json::to_value(&i).expect("serializes");
                    v["timings"] = serde_json::to_value(&t).expect("serializes");
                    json(201, &v)
                }),
                Err(e) => Err(e),
            }
        }
        (&Method::POST, ["v1", "containers", name, "destroy"]) => {
            let name = name.to_string();
            match body::<DestroyRequest>(req).await {
                Ok(d) => engine.destroy(&name, d.error).await.map(|e| json(200, &e)),
                Err(e) => Err(e),
            }
        }
        (&Method::POST, ["v1", "containers", name, "signal"]) => {
            let name = name.to_string();
            match body::<SignalRequest>(req).await {
                Ok(s) => engine.signal(&name, s.signal).await.map(|()| empty(204)),
                Err(e) => Err(e),
            }
        }
        (&Method::POST, ["v1", "containers", name, "exec"]) => {
            let name = name.to_string();
            let upgrading = req.headers().get("upgrade").and_then(|v| v.to_str().ok()) == Some(crate::exec_stream::UPGRADE);
            let on_upgrade = hyper::upgrade::on(&mut req);
            match body::<ExecRequest>(req).await {
                Ok(_) if !upgrading => Err(ApiError::Invalid(format!("exec upgrades to {}", crate::exec_stream::UPGRADE))),
                Ok(x) => engine.exec_open(&name, x).await.map(|(session, pid)| {
                    tokio::spawn(async move {
                        if let Ok(up) = on_upgrade.await {
                            super::exec::bridge(up, session, pid).await;
                        }
                    });
                    switching()
                }),
                Err(e) => Err(e),
            }
        }
        (&Method::GET, ["v1", "containers", name, "wait"]) => engine.wait(name).await.map(|e| json(200, &e)),
        (&Method::GET, ["v1", "containers", name, "logs"]) => engine.logs(name).map(|l| json(200, &l)),
        (&Method::POST, ["v1", "containers", name, "reclaim"]) => {
            engine.reclaim(name).await.map(|(b, a)| json(200, &serde_json::json!({"freeKibBefore": b, "freeKibAfter": a})))
        }
        (&Method::PUT, ["v1", "containers", name, "intercepts"]) => {
            let name = name.to_string();
            match body::<InterceptsRequest>(req).await {
                Ok(i) => engine.set_intercepts(&name, i.intercepts).map(|()| empty(204)),
                Err(e) => Err(e),
            }
        }
        (&Method::POST, ["v1", "containers", name, "snapshots"]) => {
            let name = name.to_string();
            match body::<SnapshotRequest>(req).await {
                Ok(s) => engine.snapshot(&name, s.name).await.map(|s| json(201, &s)),
                Err(e) => Err(e),
            }
        }
        (&Method::GET, ["v1", "snapshots"]) => Ok(json(200, &engine.snapshots())),
        (&Method::DELETE, ["v1", "snapshots", id]) => engine.delete_snapshot(id).map(|()| empty(204)),
        (&Method::GET, ["v1", "images"]) => Ok(json(200, &engine.images())),
        (&Method::POST, ["v1", "images", "load"]) => {
            let reference = query.split('&').find_map(|q| q.strip_prefix("reference=")).map(str::to_string);
            match save_body(&engine, req).await {
                Ok(path) => engine.load(reference, path).await.map(|m| json(200, &m)),
                Err(e) => Err(e),
            }
        }
        (&Method::DELETE, ["v1", "data", disk]) => engine.delete_data(disk).map(|()| empty(204)),
        (&Method::POST, ["v1", "images", "pull"]) => match body::<serde_json::Value>(req).await {
            Ok(v) => match v["reference"].as_str() {
                Some(r) => engine.pull(r).await.map(|m| json(200, &m)),
                None => Err(ApiError::Invalid("{\"reference\": ...}".into())),
            },
            Err(e) => Err(e),
        },
        _ => Err(ApiError::NotFound(format!("no route {method} {}", path.join("/")))),
    };
    Ok(r.unwrap_or_else(error))
}

/// Serves the API until the process ends.
pub async fn serve(engine: Arc<Engine>, listener: tokio::net::UnixListener) {
    // Unbounded by design: the engine serves for its life; each
    // connection is its own task.
    loop {
        let Ok((s, _)) = listener.accept().await else { continue };
        let engine = engine.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| route(engine.clone(), req));
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).with_upgrades().await;
        });
    }
}
