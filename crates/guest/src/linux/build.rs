//! Build mode: the guest unpacks an image's layers into the target disk,
//! applying whiteouts, with each file's owner, mode, and time as the layer
//! says. A hostile layer is parsed only here, inside a VM whose one
//! writable disk is the target.

use std::collections::HashSet;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sandcastle_wire::{
    decode_message, write_message, ErrorKind, Event, FrameReader, Kind, Reply, Request, WireError, LAYER_BYTES_MAX,
};

use super::init::{InitError, Lifecycle};
use super::sys;
use crate::layer::{classify, compression, Compression, Entry};
use crate::mounts;

/// A layer's bytes as the host streams them: stdin frames, ended by an
/// empty one, no more than declared.
struct LayerBytes<'a> {
    frames: &'a mut FrameReader<std::os::unix::net::UnixStream>,
    chunk: Vec<u8>,
    at: usize,
    remaining: u64,
    done: bool,
}

impl Read for LayerBytes<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        // Bounded: each pass returns bytes or reads one more frame of a
        // stream limited to `remaining`.
        loop {
            if self.at < self.chunk.len() {
                let n = out.len().min(self.chunk.len() - self.at);
                out[..n].copy_from_slice(&self.chunk[self.at..self.at + n]);
                self.at += n;
                return Ok(n);
            }
            if self.done {
                return Ok(0);
            }
            let f = self.frames.read_frame().map_err(|e| io::Error::other(e.to_string()))?;
            if f.kind != Kind::Stdin {
                return Err(io::Error::other("a layer's bytes are stdin frames"));
            }
            if f.payload.is_empty() {
                self.done = true;
                continue;
            }
            let n = f.payload.len() as u64;
            if n > self.remaining {
                return Err(io::Error::other("the layer is longer than declared"));
            }
            self.remaining -= n;
            self.chunk = f.payload;
            self.at = 0;
        }
    }
}

#[derive(Default)]
struct Applied {
    entries: u64,
    whiteouts: u64,
    skipped: u64,
}

fn remove_all(p: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn apply(src: impl Read, c: Compression, target: &Path) -> io::Result<Applied> {
    let decoded: Box<dyn Read> = match c {
        Compression::None => Box::new(src),
        Compression::Gzip => Box::new(flate2::read::MultiGzDecoder::new(src)),
        Compression::Zstd => Box::new(
            ruzstd::decoding::StreamingDecoder::new(src).map_err(|e| io::Error::other(format!("zstd: {e}")))?,
        ),
    };
    let mut archive = tar::Archive::new(decoded);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.set_preserve_mtime(true);
    archive.set_overwrite(true);
    archive.set_unpack_xattrs(false);
    let mut written: HashSet<PathBuf> = HashSet::new();
    let mut applied = Applied::default();
    // Bounded by the layer's declared size.
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        match classify(&path) {
            Entry::Skip(_) => applied.skipped += 1,
            Entry::Whiteout(p) => {
                if !written.contains(&p) {
                    remove_all(&target.join(&p))?;
                }
                applied.whiteouts += 1;
            }
            Entry::Opaque(dir) => {
                let at = target.join(&dir);
                if let Ok(children) = std::fs::read_dir(&at) {
                    for child in children.flatten() {
                        let rel = dir.join(child.file_name());
                        if !written.contains(&rel) {
                            remove_all(&child.path())?;
                        }
                    }
                }
                applied.whiteouts += 1;
            }
            Entry::Normal(p) => {
                let ty = entry.header().entry_type();
                if ty.is_block_special() || ty.is_character_special() || ty.is_fifo() {
                    // /dev is the init's at run time; images' device nodes
                    // are not unpacked.
                    applied.skipped += 1;
                    continue;
                }
                let at = target.join(&p);
                if let Ok(existing) = std::fs::symlink_metadata(&at) {
                    let replace = if ty.is_dir() { !existing.is_dir() } else { existing.is_dir() };
                    if replace {
                        remove_all(&at)?;
                    }
                }
                if entry.unpack_in(target)? {
                    applied.entries += 1;
                    written.insert(p);
                } else {
                    applied.skipped += 1;
                }
            }
        }
    }
    // What follows the archive's end (its padding) is read and dropped, so
    // the host's writes complete.
    io::copy(&mut archive.into_inner(), &mut io::sink())?;
    Ok(applied)
}

pub fn run(life: &mut Lifecycle) -> Result<std::convert::Infallible, InitError> {
    let io_err = |what: &'static str| move |e: io::Error| InitError::Io(what, e);
    for d in mounts::dirs_after_basics(true) {
        sys::mkdir_p(d).map_err(io_err("mkdir"))?;
    }
    sys::mount(&mounts::build_target()).map_err(io_err("mounting the target"))?;
    let listener = sys::vsock_listen(sandcastle_wire::PORT_AGENT, false).map_err(io_err("listening"))?;
    life.send(&Event::Ready { uptime_ms: sys::uptime_ms() })?;
    let target = Path::new(mounts::TARGET);
    let mut total = 0u64;
    // Unbounded by design: the host drives the build, one request per
    // connection, until it sends Finish.
    loop {
        let fd = sys::accept(std::os::fd::AsRawFd::as_raw_fd(&listener), false).map_err(io_err("accept"))?;
        let mut w = std::os::unix::net::UnixStream::from(fd);
        let mut frames = FrameReader::new(w.try_clone().map_err(io_err("clone"))?);
        let req: Result<Request, WireError> = frames.read_frame().and_then(|f| decode_message(&f));
        let reply = match req {
            Err(e) => Reply::error(ErrorKind::Invalid, e.to_string()),
            Ok(Request::Ping) => Reply::Pong { uptime_ms: sys::uptime_ms() },
            Ok(Request::Layer { media_type, bytes, .. }) => match compression(&media_type) {
                None => Reply::error(ErrorKind::Invalid, format!("media type {media_type}")),
                Some(c) => {
                    assert!(bytes <= LAYER_BYTES_MAX, "validated on decode");
                    let src = LayerBytes { frames: &mut frames, chunk: Vec::new(), at: 0, remaining: bytes, done: false };
                    match apply(src, c, target) {
                        Ok(a) => {
                            total += a.entries;
                            eprintln!("build: layer applied: {} entries, {} whiteouts, {} skipped", a.entries, a.whiteouts, a.skipped);
                            Reply::LayerApplied { entries: a.entries, whiteouts: a.whiteouts }
                        }
                        Err(e) => Reply::error(ErrorKind::Io, format!("unpacking: {e}")),
                    }
                }
            },
            Ok(Request::Finish) => {
                // SAFETY: sync(2) has no preconditions.
                unsafe { libc::sync() };
                sys::umount(mounts::TARGET).map_err(io_err("unmounting the target"))?;
                let _ = write_message(&mut w, &Reply::Finished { entries: total });
                sys::poweroff();
            }
            Ok(_) => Reply::error(ErrorKind::Invalid, "a build guest only builds"),
        };
        let _ = write_message(&mut w, &reply);
    }
}
