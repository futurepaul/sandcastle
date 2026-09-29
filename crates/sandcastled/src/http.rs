//! Response helpers shared by the API and the proxy.

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use sandcastle_proto::ApiError;

pub type Body = BoxBody<Bytes, hyper::Error>;

pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).map_err(|never| match never {}).boxed()
}

pub fn json<T: serde::Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    let body = serde_json::to_vec(value).expect("wire types serialize");
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(full(body))
        .expect("a static response builds")
}

pub fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response<Body> {
    json(status, &ApiError { code: code.to_string(), message: message.into() })
}

pub fn text(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("cache-control", "no-store")
        .body(full(message.to_string()))
        .expect("a static response builds")
}
