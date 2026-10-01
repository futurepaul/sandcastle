//! The engine's client: its API from another process on the node (the
//! spike's driver, celld). Lifecycle calls go to the engine; exec and
//! ports go to the agent socket `inspect` names, with
//! `sandcastle_vm::client`.

use std::path::{Path, PathBuf};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use crate::api::{DestroyRequest, ErrorBody, Exit, Info, InterceptsRequest, SignalRequest, Snapshot, SnapshotRequest, StartRequest};

/// An answer, as read.
const ANSWER_BYTES_MAX: usize = 16 << 20;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("connecting to the engine at {0}: {1}")]
    Connect(PathBuf, std::io::Error),
    #[error("the engine's connection: {0}")]
    Http(String),
    #[error("{status} {kind}: {message}")]
    Api { status: u16, kind: String, message: String },
    #[error("the engine's answer: {0}")]
    Decode(String),
}

impl EngineError {
    pub fn status(&self) -> Option<u16> {
        match self {
            EngineError::Api { status, .. } => Some(*status),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct EngineClient {
    socket: PathBuf,
}

impl EngineClient {
    pub fn new(socket: impl Into<PathBuf>) -> EngineClient {
        EngineClient { socket: socket.into() }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    async fn call(&self, method: &str, path: &str, body: Option<Vec<u8>>) -> Result<(u16, Bytes), EngineError> {
        let s = tokio::net::UnixStream::connect(&self.socket).await.map_err(|e| EngineError::Connect(self.socket.clone(), e))?;
        let (mut send, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.map_err(|e| EngineError::Http(e.to_string()))?;
        tokio::spawn(conn);
        let mut req = Request::builder().method(method).uri(path).header("host", "engine");
        if body.is_some() {
            req = req.header("content-type", "application/json");
        }
        let req = req.body(Full::new(Bytes::from(body.unwrap_or_default()))).map_err(|e| EngineError::Http(e.to_string()))?;
        let resp = send.send_request(req).await.map_err(|e| EngineError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let bytes = http_body_util::Limited::new(resp.into_body(), ANSWER_BYTES_MAX)
            .collect()
            .await
            .map_err(|_| EngineError::Http("an answer too large or cut off".into()))?
            .to_bytes();
        if status >= 400 {
            let e: ErrorBody = serde_json::from_slice(&bytes).map_err(|e| EngineError::Decode(e.to_string()))?;
            return Err(EngineError::Api { status, kind: e.kind, message: e.error });
        }
        Ok((status, bytes))
    }

    async fn json<T: DeserializeOwned>(&self, method: &str, path: &str, body: Option<&impl Serialize>) -> Result<T, EngineError> {
        let body = body.map(|b| serde_json::to_vec(b).expect("serializes"));
        let (_, bytes) = self.call(method, path, body).await?;
        serde_json::from_slice(&bytes).map_err(|e| EngineError::Decode(e.to_string()))
    }

    pub async fn health(&self) -> Result<serde_json::Value, EngineError> {
        self.json("GET", "/v1/health", None::<&()>).await
    }

    pub async fn start(&self, name: &str, req: &StartRequest, wait_ready: bool) -> Result<Info, EngineError> {
        let q = if wait_ready { "?wait=ready" } else { "" };
        self.json("POST", &format!("/v1/containers/{name}/start{q}"), Some(req)).await
    }

    /// `inspect()`: `None` when no container of that name runs.
    pub async fn inspect(&self, name: &str) -> Result<Option<Info>, EngineError> {
        match self.json("GET", &format!("/v1/containers/{name}"), None::<&()>).await {
            Ok(i) => Ok(Some(i)),
            Err(e) if e.status() == Some(404) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn list(&self) -> Result<Vec<Info>, EngineError> {
        self.json("GET", "/v1/containers", None::<&()>).await
    }

    pub async fn destroy(&self, name: &str, error: Option<String>) -> Result<Exit, EngineError> {
        self.json("POST", &format!("/v1/containers/{name}/destroy"), Some(&DestroyRequest { error })).await
    }

    pub async fn signal(&self, name: &str, signal: i32) -> Result<(), EngineError> {
        let body = serde_json::to_vec(&SignalRequest { signal }).expect("serializes");
        self.call("POST", &format!("/v1/containers/{name}/signal"), Some(body)).await.map(|_| ())
    }

    pub async fn wait(&self, name: &str) -> Result<Exit, EngineError> {
        self.json("GET", &format!("/v1/containers/{name}/wait"), None::<&()>).await
    }

    /// The tail of the container's stdout and stderr.
    pub async fn logs(&self, name: &str) -> Result<serde_json::Value, EngineError> {
        self.json("GET", &format!("/v1/containers/{name}/logs"), None::<&()>).await
    }

    pub async fn reclaim(&self, name: &str) -> Result<serde_json::Value, EngineError> {
        self.json("POST", &format!("/v1/containers/{name}/reclaim"), None::<&()>).await
    }

    pub async fn set_intercepts(&self, name: &str, intercepts: Vec<sandcastle_egress::Intercept>) -> Result<(), EngineError> {
        let body = serde_json::to_vec(&InterceptsRequest { intercepts }).expect("serializes");
        self.call("PUT", &format!("/v1/containers/{name}/intercepts"), Some(body)).await.map(|_| ())
    }

    pub async fn snapshot(&self, name: &str, snapshot_name: Option<String>) -> Result<Snapshot, EngineError> {
        self.json("POST", &format!("/v1/containers/{name}/snapshots"), Some(&SnapshotRequest { name: snapshot_name })).await
    }

    pub async fn snapshots(&self) -> Result<Vec<Snapshot>, EngineError> {
        self.json("GET", "/v1/snapshots", None::<&()>).await
    }

    pub async fn delete_snapshot(&self, id: &str) -> Result<(), EngineError> {
        self.call("DELETE", &format!("/v1/snapshots/{id}"), None).await.map(|_| ())
    }

    pub async fn delete_data(&self, disk: &str) -> Result<(), EngineError> {
        self.call("DELETE", &format!("/v1/data/{disk}"), None).await.map(|_| ())
    }

    /// `start`, and the engine's account of where its time went.
    pub async fn start_timed(&self, name: &str, req: &StartRequest) -> Result<(Info, serde_json::Value), EngineError> {
        let v: serde_json::Value = self.json("POST", &format!("/v1/containers/{name}/start?wait=ready"), Some(req)).await?;
        let timings = v.get("timings").cloned().unwrap_or(serde_json::Value::Null);
        let info: Info = serde_json::from_value(v).map_err(|e| EngineError::Decode(e.to_string()))?;
        Ok((info, timings))
    }

    /// Loads a `docker save` tar under `reference`.
    pub async fn load(&self, reference: &str, tar: Vec<u8>) -> Result<serde_json::Value, EngineError> {
        let (_, bytes) = self.call("POST", &format!("/v1/images/load?reference={reference}"), Some(tar)).await?;
        serde_json::from_slice(&bytes).map_err(|e| EngineError::Decode(e.to_string()))
    }

    pub async fn pull(&self, reference: &str) -> Result<serde_json::Value, EngineError> {
        self.json("POST", "/v1/images/pull", Some(&serde_json::json!({"reference": reference}))).await
    }
}
