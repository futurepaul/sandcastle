//! E6: `exec` through the engine's API (`exec_stream`), as celld calls it:
//! the streams and the exit, stdin, a PTY and its resize, a signal,
//! Cloudflare's env rule, a refused command, and the round trip.

use std::time::Instant;

use hyper_util::rt::TokioIo;
use sandcastle_engine::exec_stream::{self, Decoder, Exited, Resize, Signal, Started, Stream};
use sandcastle_engine::{ExecRequest, PtySize};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::launch::ms;
use crate::node::{engine_err, start, Node};
use crate::scenarios::{BUSYBOX, SLEEP_FOREVER};
use crate::{stats, Error};

/// What one exec gave back.
#[derive(Default, Debug)]
struct Ran {
    pid: u32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit: Option<Exited>,
    error: Option<String>,
    started_ms: f64,
    total_ms: f64,
}

/// One input step: frames to send, after waiting for this much output.
struct Step {
    after_stdout: &'static str,
    frames: Vec<Vec<u8>>,
}

async fn run(node: &Node, name: &str, req: &ExecRequest, steps: Vec<Step>) -> Result<Ran, Error> {
    let t0 = Instant::now();
    let up = node.client.exec(name, req).await.map_err(engine_err)?;
    let (mut rd, mut wr) = tokio::io::split(TokioIo::new(up));
    let mut ran = Ran { started_ms: ms(t0, Instant::now()), ..Ran::default() };
    let mut steps = steps.into_iter().peekable();
    let mut d = Decoder::default();
    let mut buf = vec![0u8; 64 * 1024];
    // Bounded by the exit frame, or by the engine closing the stream.
    loop {
        while let Some(s) = steps.peek() {
            if !String::from_utf8_lossy(&ran.stdout).contains(s.after_stdout) {
                break;
            }
            for f in &steps.next().expect("peeked").frames {
                wr.write_all(f).await.map_err(Error::io("a frame"))?;
            }
        }
        let n = rd.read(&mut buf).await.map_err(Error::io("the stream"))?;
        if n == 0 {
            break;
        }
        d.push(&buf[..n]);
        while let Some((stream, payload)) = d.next_frame().map_err(|e| Error::msg(e.to_string()))? {
            match stream {
                Stream::Started => ran.pid = exec_stream::decode_json::<Started>(stream, &payload).map_err(|e| Error::msg(e.to_string()))?.pid,
                Stream::Stdout => ran.stdout.extend(payload),
                Stream::Stderr => ran.stderr.extend(payload),
                Stream::Exited => ran.exit = Some(exec_stream::decode_json(stream, &payload).map_err(|e| Error::msg(e.to_string()))?),
                Stream::Error => ran.error = Some(String::from_utf8_lossy(&payload).into_owned()),
                other => return Err(Error::msg(format!("the engine sent {other:?}"))),
            }
        }
    }
    ran.total_ms = ms(t0, Instant::now());
    Ok(ran)
}

fn req(cmd: &[&str]) -> ExecRequest {
    ExecRequest { cmd: cmd.iter().map(|s| s.to_string()).collect(), ..ExecRequest::default() }
}

pub fn scenario(node: &Node) -> Result<Value, Error> {
    let mut s = start(BUSYBOX, SLEEP_FOREVER);
    s.env = [("FOO".to_string(), "from-start".to_string())].into();
    let c = node.start("exec-api", &s)?;
    let name = c.name.clone();
    let mut checks = serde_json::Map::new();
    let mut check = |k: &str, v: bool| {
        checks.insert(k.into(), json!(v));
    };

    let r = node.block(run(node, &name, &req(&["sh", "-c", "echo out; echo err >&2; exit 7"]), vec![]))?;
    check("streams_and_exit", r.stdout == b"out\n" && r.stderr == b"err\n" && r.exit == Some(Exited { code: Some(7), signal: None }) && r.pid > 0);

    let mut x = req(&["cat"]);
    x.stdin = true;
    let r = node.block(run(node, &name, &x, vec![Step { after_stdout: "", frames: vec![exec_stream::encode(Stream::Stdin, b"piped"), exec_stream::encode(Stream::Stdin, b"")] }]))?;
    check("stdin_piped_and_closed", r.stdout == b"piped" && r.exit.is_some_and(|e| e.code == Some(0)));

    let mut x = req(&["sh", "-c", "stty size; read x; stty size"]);
    x.stdin = true;
    x.pty = Some(PtySize { cols: 50, rows: 20 });
    let resize = exec_stream::encode_json(Stream::Resize, &Resize { cols: 90, rows: 30 });
    let r = node.block(run(node, &name, &x, vec![Step { after_stdout: "20 50", frames: vec![resize, exec_stream::encode(Stream::Stdin, b"\n")] }]))?;
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    check("pty_sized_and_resized", out.contains("20 50") && out.contains("30 90"));

    let mut x = req(&["sh", "-c", "echo up; sleep 100"]);
    x.stdin = true;
    let r = node.block(run(node, &name, &x, vec![Step { after_stdout: "up", frames: vec![exec_stream::encode_json(Stream::Signal, &Signal { signal: 9 })] }]))?;
    check("signal_ends_it", r.exit.is_some_and(|e| e.signal == Some(9) || e.code == Some(137)));

    let r = node.block(run(node, &name, &req(&["sh", "-c", "echo \"$PATH|$FOO\""]), vec![]))?;
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    check("env_inherits_path_only", out.starts_with('/') && out.trim_end().ends_with('|'));

    let mut x = req(&["sh", "-c", "echo \"$FOO\""]);
    x.env = [("FOO".to_string(), "from-exec".to_string())].into();
    let r = node.block(run(node, &name, &x, vec![]))?;
    check("env_given_to_exec", r.stdout == b"from-exec\n");

    let refused = node.block(node.client.exec(&name, &req(&["/no/such/binary"])));
    check("missing_binary_refused", matches!(&refused, Err(e) if e.status() == Some(400)));

    let mut started = vec![];
    let mut total = vec![];
    for _ in 0..20 {
        let r = node.block(run(node, &name, &req(&["true"]), vec![]))?;
        started.push(r.started_ms);
        total.push(r.total_ms);
    }
    c.destroy(None)?;
    let pass = checks.values().all(|v| v == true);
    Ok(json!({
        "pass": pass,
        "checks": checks,
        "true_request_to_started_ms": stats(&started),
        "true_request_to_exited_ms": stats(&total),
    }))
}
