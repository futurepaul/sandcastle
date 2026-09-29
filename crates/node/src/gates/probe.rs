//! Whether a service answers its health path: an HTTP GET through its
//! host port, any status below 500 within the deadline.

use std::time::Duration;

const PROBE_DEADLINE: Duration = Duration::from_secs(2);

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
}
