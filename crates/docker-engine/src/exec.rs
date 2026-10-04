//! `exec` over the API (`sandcastle_engine::exec_stream`), as `docker exec`:
//! the upgraded connection bridged to the docker client's pipes. Its
//! output becomes stdout and stderr frames (a combined stderr is joined to
//! stdout inside the container by the relay, so the two keep their order);
//! stdin frames go to its stdin, an empty one closing it; a
//! signal goes to the process inside the container (its pid from the
//! relay's pidfile), or, failing that, ends the docker client. The
//! client's exit is the `Exited` frame, always the last.

use std::path::PathBuf;
use std::process::ExitStatus;
use std::time::Duration;

use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use sandcastle_engine::exec_stream::{self, Decoder, ErrorFrame, Exited, Signal, Started, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin};
use tokio::sync::mpsc;

/// Frames queued toward the client.
const QUEUE: usize = 16;
/// A read from the client's pipes, at most: one frame's payload.
const CHUNK_BYTES: usize = 64 << 10;
const _: () = assert!(CHUNK_BYTES <= exec_stream::PAYLOAD_BYTES_MAX);
/// After the client exits, its output's last bytes, at most this long.
const DRAIN_WAIT: Duration = Duration::from_secs(5);

/// What the exec's end reports: the client's exit, read. A code of 128+n
/// after the double sent signal n is that signal (as Docker reports one);
/// a client the double had to end reports the signal it was sent.
pub fn exited(code: Option<i32>, client_signal: Option<i32>, sent: Option<i32>, client_ended: bool) -> Exited {
    match (sent, code) {
        (Some(n), _) if client_ended => Exited { code: None, signal: Some(n) },
        (Some(n), Some(c)) if c == 128 + n => Exited { code: None, signal: Some(n) },
        (_, Some(c)) => Exited { code: Some(c), signal: None },
        (_, None) => Exited { code: None, signal: Some(client_signal.unwrap_or(9)) },
    }
}

fn status_parts(s: ExitStatus) -> (Option<i32>, Option<i32>) {
    use std::os::unix::process::ExitStatusExt;
    (s.code(), s.signal())
}

/// One exec in container `docker_name`, its client `child` spawned with
/// the pipes `stdin` asks for; `pidfile` is where the relay writes the
/// process's pid, on the host's side.
pub struct Exec {
    pub name: String,
    pub docker_name: String,
    pub child: Child,
    pub pidfile: PathBuf,
    pub combined: bool,
}

async fn pump(mut r: impl AsyncRead + Unpin, stream: Stream, tx: mpsc::Sender<Vec<u8>>) -> usize {
    let mut buf = vec![0u8; CHUNK_BYTES];
    let mut total = 0;
    // Bounded by the pipe: it ends with the docker client.
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return total,
            Ok(n) => {
                total += n;
                if tx.send(exec_stream::encode(stream, &buf[..n])).await.is_err() {
                    return total;
                }
            }
        }
    }
}

/// The signal to the process inside the container; false when that could
/// not be done (no pid yet, the image has no `kill`).
async fn signal_inside(docker_name: &str, pidfile: &std::path::Path, signal: i32) -> bool {
    let Some(pid) = tokio::fs::read_to_string(pidfile).await.ok().and_then(|p| p.trim().parse::<u32>().ok()) else { return false };
    crate::docker::call("exec kill", &crate::docker::kill_args(docker_name, signal, pid)).await.is_ok()
}

pub async fn bridge(x: Exec, upgraded: Upgraded) {
    let Exec { name, docker_name, mut child, pidfile, combined } = x;
    let pid = child.id().unwrap_or(0);
    let (mut from_client, mut to_client) = tokio::io::split(TokioIo::new(upgraded));
    let (frames_tx, mut frames) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (signals, mut signals_rx) = mpsc::channel::<i32>(1);
    let stdin: Option<ChildStdin> = child.stdin.take();
    let out = child.stdout.take().map(|o| tokio::spawn(pump(o, Stream::Stdout, frames_tx.clone())));
    let err = child.stderr.take().map(|e| tokio::spawn(pump(e, if combined { Stream::Stdout } else { Stream::Stderr }, frames_tx.clone())));
    let _ = frames_tx.send(exec_stream::encode_json(Stream::Started, &Started { pid })).await;

    // The process's end: its exit, then its output's last bytes, then the
    // exit's frame. Bounded by the client's life.
    let (n, dn, pf) = (name.clone(), docker_name.clone(), pidfile.clone());
    let ending = tokio::spawn(async move {
        let (mut sent, mut client_ended) = (None, false);
        // Bounded by the client's exit; each signal is one more turn.
        let status = loop {
            tokio::select! {
                s = child.wait() => break s,
                Some(signal) = signals_rx.recv() => {
                    sent = Some(signal);
                    if !signal_inside(&dn, &pf, signal).await {
                        let _ = child.start_kill();
                        client_ended = true;
                    }
                }
            }
        };
        let mut bytes = 0;
        for t in [out, err].into_iter().flatten() {
            if let Ok(Ok(b)) = tokio::time::timeout(DRAIN_WAIT, t).await {
                bytes += b;
            }
        }
        let frame = match status {
            Ok(s) => {
                let (code, client_signal) = status_parts(s);
                let e = exited(code, client_signal, sent, client_ended);
                crate::note(&n, format!("exec pid {pid}: {bytes} bytes out, exited {e:?}"));
                exec_stream::encode_json(Stream::Exited, &e)
            }
            Err(e) => exec_stream::encode_json(Stream::Error, &ErrorFrame { error: format!("the docker client: {e}") }),
        };
        let _ = frames_tx.send(frame).await;
    });

    let reading = async move {
        let mut d = Decoder::default();
        let mut buf = vec![0u8; CHUNK_BYTES];
        let mut stdin = stdin;
        // Bounded by the client's side of the connection.
        loop {
            let n = match from_client.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            d.push(&buf[..n]);
            // Bounded by the bytes just read.
            loop {
                let (stream, payload) = match d.next_frame() {
                    Ok(Some(f)) => f,
                    Ok(None) => break,
                    Err(_) => return,
                };
                match stream {
                    // an empty frame is stdin's EOF: dropping the pipe closes it
                    Stream::Stdin if payload.is_empty() => stdin = None,
                    Stream::Stdin => {
                        if let Some(s) = stdin.as_mut() {
                            if s.write_all(&payload).await.is_err() {
                                stdin = None;
                            }
                        }
                    }
                    // no terminal, so nothing to size
                    Stream::Resize => {}
                    Stream::Signal => match exec_stream::decode_json::<Signal>(stream, &payload) {
                        Ok(s) if sandcastle_engine::api::validate_signal(s.signal).is_ok() => {
                            if signals.send(s.signal).await.is_err() {
                                return;
                            }
                        }
                        _ => return,
                    },
                    _ => return,
                }
            }
        }
        // The client is done sending: whatever stdin it left open ends.
    };
    let writing = async move {
        // Bounded by the frames' senders, which end with the process.
        while let Some(f) = frames.recv().await {
            if to_client.write_all(&f).await.is_err() {
                return;
            }
        }
        let _ = to_client.shutdown().await;
    };
    // The exit's frame ends the exchange; a client that stops sending
    // first still gets the output to the end.
    tokio::pin!(writing);
    tokio::select! {
        _ = &mut writing => {}
        _ = reading => writing.await,
    }
    // A client gone before the exit: its docker client ends with it.
    ending.abort();
    let _ = tokio::fs::remove_file(&pidfile).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: an exec's end as the engine reports one: a code, a signal the
    // double sent (128+n, as Docker gives it), and a client it had to end.
    #[test]
    fn exits() {
        assert_eq!(exited(Some(0), None, None, false), Exited { code: Some(0), signal: None });
        assert_eq!(exited(Some(143), None, None, false), Exited { code: Some(143), signal: None }, "no signal sent: a code");
        assert_eq!(exited(Some(143), None, Some(15), false), Exited { code: None, signal: Some(15) });
        assert_eq!(exited(Some(0), None, Some(15), false), Exited { code: Some(0), signal: None }, "it caught the signal and exited");
        assert_eq!(exited(None, Some(9), Some(15), true), Exited { code: None, signal: Some(15) }, "the client ended for it");
        assert_eq!(exited(None, Some(6), None, false), Exited { code: None, signal: Some(6) });
    }
}
