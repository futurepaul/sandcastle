//! `exec` over the API (`crate::exec_stream`): the upgraded connection
//! bridged to the guest agent's session. The agent's client is blocking,
//! so its two halves run on blocking threads; the connection's two
//! directions are tasks.

use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use sandcastle_vm::client::{ExecEvent, ExecSession};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::exec_stream::{self, Decoder, ErrorFrame, Exited, Resize, Signal, Started, Stream};

/// Frames queued toward the client, and commands toward the guest.
const QUEUE: usize = 16;

enum Command {
    Stdin(Vec<u8>),
    CloseStdin,
    Resize(Resize),
    Signal(i32),
}

pub async fn bridge(upgraded: Upgraded, session: ExecSession, pid: u32) {
    let (mut from_client, mut to_client) = tokio::io::split(TokioIo::new(upgraded));
    let (mut writer, mut reader) = session.split();
    let (frames_tx, mut frames) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (commands, mut commands_rx) = mpsc::channel::<Command>(QUEUE);

    // The guest's output and its end, toward the client. Bounded by the
    // process's life: the agent's stream ends with its exit.
    let started = exec_stream::encode_json(Stream::Started, &Started { pid });
    let events = tokio::task::spawn_blocking(move || {
        if frames_tx.blocking_send(started).is_err() {
            return;
        }
        loop {
            let frame = match reader.next_event() {
                Ok(ExecEvent::Stdout(b)) => chunks(Stream::Stdout, &b),
                Ok(ExecEvent::Stderr(b)) => chunks(Stream::Stderr, &b),
                Ok(ExecEvent::Exited { code, signal }) => {
                    let _ = frames_tx.blocking_send(exec_stream::encode_json(Stream::Exited, &Exited { code, signal }));
                    return;
                }
                Ok(ExecEvent::Started(_)) => vec![exec_stream::encode_json(Stream::Error, &ErrorFrame { error: "a second start".into() })],
                Err(e) => {
                    let _ = frames_tx.blocking_send(exec_stream::encode_json(Stream::Error, &ErrorFrame { error: e.to_string() }));
                    return;
                }
            };
            for f in frame {
                if frames_tx.blocking_send(f).is_err() {
                    return;
                }
            }
        }
    });

    // The client's input, toward the guest. Bounded by the commands'
    // senders, which end with the client's side.
    let inputs = tokio::task::spawn_blocking(move || {
        while let Some(c) = commands_rx.blocking_recv() {
            let r = match c {
                Command::Stdin(b) => writer.stdin(&b),
                Command::CloseStdin => writer.close_stdin(),
                Command::Resize(r) => writer.resize(r.rows, r.cols),
                Command::Signal(s) => writer.signal(s),
            };
            if r.is_err() {
                return;
            }
        }
    });

    let reading = async move {
        let mut d = Decoder::default();
        let mut buf = vec![0u8; 64 * 1024];
        let mut stdin_open = true;
        // Bounded by the client's side of the connection.
        loop {
            let n = match from_client.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            d.push(&buf[..n]);
            loop {
                let (stream, payload) = match d.next_frame() {
                    Ok(Some(f)) => f,
                    Ok(None) => break,
                    Err(_) => return,
                };
                let c = match stream {
                    Stream::Stdin if !stdin_open => continue,
                    Stream::Stdin if payload.is_empty() => {
                        stdin_open = false;
                        Command::CloseStdin
                    }
                    Stream::Stdin => Command::Stdin(payload),
                    Stream::Resize => match exec_stream::decode_json::<Resize>(stream, &payload) {
                        Ok(r) if r.cols > 0 && r.rows > 0 => Command::Resize(r),
                        _ => return,
                    },
                    Stream::Signal => match exec_stream::decode_json::<Signal>(stream, &payload) {
                        Ok(s) if crate::api::validate_signal(s.signal).is_ok() => Command::Signal(s.signal),
                        _ => return,
                    },
                    _ => return,
                };
                if commands.send(c).await.is_err() {
                    return;
                }
            }
        }
        // The client is done sending: whatever stdin it left open ends.
        if stdin_open {
            let _ = commands.send(Command::CloseStdin).await;
        }
    };
    let writing = async move {
        // Bounded by the events, which end with the process.
        while let Some(f) = frames.recv().await {
            if to_client.write_all(&f).await.is_err() {
                return;
            }
        }
        let _ = to_client.shutdown().await;
    };
    // The exit's frame ends the exchange: a client still sending is not
    // waited for, and dropping its reader ends the input thread. A client
    // that stops sending first still gets the output to the end.
    tokio::pin!(writing);
    tokio::select! {
        _ = &mut writing => {}
        _ = reading => writing.await,
    }
    let _ = events.await;
    let _ = inputs.await;
}

fn chunks(stream: Stream, data: &[u8]) -> Vec<Vec<u8>> {
    data.chunks(exec_stream::PAYLOAD_BYTES_MAX).map(|c| exec_stream::encode(stream, c)).collect()
}
