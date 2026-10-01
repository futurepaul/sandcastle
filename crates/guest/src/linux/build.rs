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
    specials: u64,
    xattrs: u64,
}

fn remove_all(p: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// zstd's frames one after another, as `zstd` and `zstd:chunked` write
/// them, skippable frames (`zstd:chunked`'s table of contents) skipped.
struct MultiZstd<R: Read> {
    src: Option<io::BufReader<R>>,
    frame: Option<ruzstd::decoding::StreamingDecoder<io::BufReader<R>, ruzstd::decoding::FrameDecoder>>,
}

/// Skippable frames' magic numbers: 0x184D2A50 to 0x184D2A5F.
fn skippable(magic: u32) -> bool {
    magic & 0xFFFF_FFF0 == 0x184D_2A50
}

impl<R: Read> MultiZstd<R> {
    fn new(r: R) -> MultiZstd<R> {
        MultiZstd { src: Some(io::BufReader::with_capacity(1 << 16, r)), frame: None }
    }

    /// The next data frame's decoder, or `None` at the end of the stream.
    fn next_frame(&mut self) -> io::Result<bool> {
        use io::BufRead;
        let mut src = self.src.take().expect("a source between frames");
        // Bounded by the stream: each pass consumes a skippable frame.
        loop {
            let head = src.fill_buf()?;
            if head.is_empty() {
                return Ok(false);
            }
            let mut magic = [0u8; 8];
            let n = head.len().min(8);
            magic[..n].copy_from_slice(&head[..n]);
            if n >= 4 && skippable(u32::from_le_bytes([magic[0], magic[1], magic[2], magic[3]])) {
                let mut hdr = [0u8; 8];
                src.read_exact(&mut hdr)?;
                let len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as u64;
                io::copy(&mut (&mut src).take(len), &mut io::sink())?;
                continue;
            }
            let d = ruzstd::decoding::StreamingDecoder::new(src).map_err(|e| io::Error::other(format!("zstd: {e}")))?;
            self.frame = Some(d);
            return Ok(true);
        }
    }
}

impl<R: Read> Read for MultiZstd<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        // Bounded by the stream's frames.
        loop {
            if let Some(f) = self.frame.as_mut() {
                let n = f.read(out)?;
                if n > 0 || out.is_empty() {
                    return Ok(n);
                }
                let done = self.frame.take().expect("a frame");
                self.src = Some(done.into_inner());
            }
            if self.src.is_none() || !self.next_frame()? {
                return Ok(0);
            }
        }
    }
}

/// A device node or a FIFO, as the layer gives it: made, owned, and dated.
fn special(entry: &tar::Entry<'_, impl Read>, at: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let h = entry.header();
    let ty = h.entry_type();
    let mode = h.mode()? & 0o7777;
    let kind = if ty.is_character_special() {
        libc::S_IFCHR
    } else if ty.is_block_special() {
        libc::S_IFBLK
    } else {
        libc::S_IFIFO
    };
    let dev = libc::makedev(h.device_major()?.unwrap_or(0), h.device_minor()?.unwrap_or(0));
    let c = std::ffi::CString::new(at.as_os_str().as_bytes()).map_err(|_| io::Error::other("a NUL in a path"))?;
    // SAFETY: mknod and lchown with a NUL-terminated path.
    unsafe {
        super::sys::check(libc::mknod(c.as_ptr(), kind | mode, dev))?;
        super::sys::check(libc::lchown(c.as_ptr(), h.uid()? as u32, h.gid()? as u32))?;
    }
    Ok(())
}

/// Extended attributes from the entry's PAX records (`SCHILY.xattr.*`),
/// file capabilities among them, set on what was unpacked.
fn xattrs(pax: &[(String, Vec<u8>)], at: &Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(at.as_os_str().as_bytes()).map_err(|_| io::Error::other("a NUL in a path"))?;
    let mut set = 0;
    for (k, v) in pax {
        let Some(name) = k.strip_prefix("SCHILY.xattr.") else { continue };
        let n = std::ffi::CString::new(name).map_err(|_| io::Error::other("a NUL in an xattr"))?;
        // SAFETY: lsetxattr with NUL-terminated strings and a borrowed value.
        super::sys::check(unsafe { libc::lsetxattr(c.as_ptr(), n.as_ptr(), v.as_ptr() as *const libc::c_void, v.len(), 0) })?;
        set += 1;
    }
    Ok(set)
}

fn apply(src: impl Read, c: Compression, target: &Path) -> io::Result<Applied> {
    let decoded: Box<dyn Read> = match c {
        Compression::None => Box::new(src),
        Compression::Gzip => Box::new(flate2::read::MultiGzDecoder::new(src)),
        Compression::Zstd => Box::new(MultiZstd::new(src)),
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
                let pax: Vec<(String, Vec<u8>)> = match entry.pax_extensions()? {
                    Some(exts) => exts
                        .filter_map(|e| e.ok())
                        .filter_map(|e| e.key().ok().map(|k| (k.to_string(), e.value_bytes().to_vec())))
                        .collect(),
                    None => vec![],
                };
                let at = target.join(&p);
                if let Ok(existing) = std::fs::symlink_metadata(&at) {
                    let replace = if ty.is_dir() { !existing.is_dir() } else { true };
                    if replace && !(ty.is_file() && existing.is_file()) {
                        remove_all(&at)?;
                    }
                }
                if ty.is_block_special() || ty.is_character_special() || ty.is_fifo() {
                    // Inside the parent the layer named, which unpack_in
                    // would have checked; a special file has no data.
                    if !at.starts_with(target) || at.parent().is_none_or(|d| !d.is_dir()) {
                        applied.skipped += 1;
                        continue;
                    }
                    special(&entry, &at)?;
                    applied.entries += 1;
                    applied.specials += 1;
                    written.insert(p);
                } else if entry.unpack_in(target)? {
                    applied.entries += 1;
                    written.insert(p);
                } else {
                    applied.skipped += 1;
                    continue;
                }
                applied.xattrs += xattrs(&pax, &at)?;
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
                            eprintln!(
                                "build: layer applied: {} entries, {} whiteouts, {} special files, {} xattrs, {} skipped",
                                a.entries, a.whiteouts, a.specials, a.xattrs, a.skipped
                            );
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
