//! Whether a service answers its health path: an HTTP GET through its
//! host port, any status below 500 within the deadline. And whether it
//! says it is working (`sandcastle_proto::Busy`).

use std::time::Duration;

use http_body_util::BodyExt;

const PROBE_DEADLINE: Duration = Duration::from_secs(2);
/// A busy answer is a small JSON object.
const BUSY_BYTES_MAX: usize = 64 * 1024;

/// What a busy answer says: working when `field` is true or a number above
/// zero; not when it is false or zero; anything else (no answer, not JSON,
/// no such field) is working, since sleep is never worth interrupting work.
pub fn busy_says(status: u16, body: &[u8], field: &str) -> bool {
    if !(200..300).contains(&status) {
        return true;
    }
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(body) else { return true };
    match map.get(field) {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => n.as_f64().is_none_or(|x| x > 0.0),
        _ => true,
    }
}

pub struct TcpProber;

impl super::Prober for TcpProber {
    async fn probe(&self, port: u16, path: &str) -> bool {
        assert!(port > 0);
        assert!(path.starts_with('/'), "a health path is absolute (checked by the spec)");
        let attempt = async {
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
            let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await.ok()?;
            tokio::spawn(conn);
            let req = hyper::Request::get(path).header("host", "localhost").body(http_body_util::Empty::<hyper::body::Bytes>::new()).ok()?;
            let resp = send.send_request(req).await.ok()?;
            Some(resp.status().as_u16() < 500)
        };
        matches!(tokio::time::timeout(PROBE_DEADLINE, attempt).await, Ok(Some(true)))
    }

    async fn busy(&self, port: u16, path: &str, field: &str) -> bool {
        assert!(port > 0);
        assert!(path.starts_with('/'), "a busy path is absolute (checked by the spec)");
        let attempt = async {
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
            let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await.ok()?;
            tokio::spawn(conn);
            let req = hyper::Request::get(path).header("host", "localhost").body(http_body_util::Empty::<hyper::body::Bytes>::new()).ok()?;
            let resp = send.send_request(req).await.ok()?;
            let status = resp.status().as_u16();
            let body = http_body_util::Limited::new(resp.into_body(), BUSY_BYTES_MAX).collect().await.ok()?.to_bytes();
            Some(busy_says(status, &body, field))
        };
        tokio::time::timeout(PROBE_DEADLINE, attempt).await.ok().flatten().unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::busy_says;

    #[test]
    fn a_busy_answer_says_busy_unless_it_clearly_says_not() {
        for (body, want) in [
            (r#"{"active_agents": 0}"#, false),
            (r#"{"active_agents": 2}"#, true),
            (r#"{"active_agents": false}"#, false),
            (r#"{"active_agents": true}"#, true),
            (r#"{"other": 0}"#, true),
            (r#"{"active_agents": "0"}"#, true),
            (r#"[0]"#, true),
            ("not json", true),
        ] {
            assert_eq!(busy_says(200, body.as_bytes(), "active_agents"), want, "{body}");
        }
        assert!(busy_says(503, br#"{"active_agents": 0}"#, "active_agents"), "an error answer says nothing");
    }
}
