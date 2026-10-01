//! Starting processes in the workload: the entrypoint, which makes the
//! workload's mount namespace and pivots into the root as its PID
//! namespace's PID 1, and every exec after it, which joins that mount
//! namespace. The work between fork and exec is system calls only, on
//! values prepared before the fork.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::process::Stdio;

use sandcastle_wire::{Output, Process};
use tokio::process::{Child, Command};

use super::sys::{check, cstr};
use crate::env::environment;
use crate::mounts::{self, Mount};
use crate::passwd::{self, User};

const OLD_ROOT: &str = ".sc-old";

/// Who `process` runs as, from the workload's own passwd and group files.
pub fn user_of(process: &Process) -> io::Result<User> {
    let Some(spec) = &process.user else {
        return Ok(User { home: "/root".into(), ..passwd::ROOT });
    };
    let read = |f: &str| std::fs::read_to_string(format!("{}/etc/{f}", mounts::ROOT)).unwrap_or_default();
    passwd::resolve(spec, &read("passwd"), &read("group"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no user {spec} in the image")))
}

struct Prepared {
    cwd: CString,
    uid: u32,
    gid: u32,
}

fn prepare(command: &mut Command, process: &Process, tty: bool) -> io::Result<Prepared> {
    let user = user_of(process)?;
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    command.args(&process.argv[1..]).env_clear();
    for (k, v) in environment(&process.env, &user.home, hostname.trim(), tty) {
        command.env(k, v);
    }
    Ok(Prepared { cwd: cstr(process.cwd.as_deref().unwrap_or("/"))?, uid: user.uid, gid: user.gid })
}

/// The last step before exec: the workload's cwd, then its user.
fn enter(p: &Prepared) -> io::Result<()> {
    // SAFETY: system calls on prepared values, after fork.
    unsafe {
        if libc::chdir(p.cwd.as_ptr()) == -1 {
            check(libc::chdir(c"/".as_ptr()))?;
        }
        check(libc::setgroups(0, std::ptr::null()))?;
        check(libc::setgid(p.gid))?;
        check(libc::setuid(p.uid))?;
    }
    Ok(())
}

struct RawMount {
    source: CString,
    target: CString,
    fstype: Option<CString>,
    flags: libc::c_ulong,
}

fn raw(m: &Mount) -> io::Result<RawMount> {
    let mut flags = 0;
    if m.flags.read_only {
        flags |= libc::MS_RDONLY;
    }
    if m.flags.nosuid {
        flags |= libc::MS_NOSUID;
    }
    if m.flags.nodev {
        flags |= libc::MS_NODEV;
    }
    if m.flags.noexec {
        flags |= libc::MS_NOEXEC;
    }
    if m.flags.bind {
        flags |= libc::MS_BIND;
    }
    if m.flags.recursive {
        flags |= libc::MS_REC;
    }
    Ok(RawMount { source: cstr(&m.source)?, target: cstr(&m.target)?, fstype: m.fstype.map(cstr).transpose()?, flags })
}

/// Starts the entrypoint; the caller has unshared the PID namespace, so
/// this, its first fork, is the namespace's PID 1.
pub fn spawn_entrypoint(process: &Process) -> io::Result<Child> {
    for d in ["dev", "sys", "proc", OLD_ROOT] {
        super::sys::mkdir_p(&format!("{}/{d}", mounts::ROOT))?;
    }
    let mut command = Command::new(&process.argv[0]);
    let prepared = prepare(&mut command, process, false)?;
    let workload: Vec<RawMount> = mounts::workload().iter().map(raw).collect::<io::Result<_>>()?;
    let root = cstr(mounts::ROOT)?;
    let old = cstr(OLD_ROOT)?;
    let old_abs = cstr(&format!("/{OLD_ROOT}"))?;
    // Its output is the container's logs: piped to the init, which sends
    // it to the runner.
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // SAFETY: the closure makes system calls only, on values prepared
    // above, between fork and exec in a single-threaded child.
    unsafe {
        command.pre_exec(move || {
            check(libc::unshare(libc::CLONE_NEWNS))?;
            check(libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()))?;
            for m in &workload {
                let fstype = m.fstype.as_ref().map_or(std::ptr::null(), |f| f.as_ptr());
                check(libc::mount(m.source.as_ptr(), m.target.as_ptr(), fstype, m.flags, std::ptr::null()))?;
            }
            check(libc::chdir(root.as_ptr()))?;
            check(libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), old.as_ptr()) as libc::c_int)?;
            check(libc::chdir(c"/".as_ptr()))?;
            check(libc::umount2(old_abs.as_ptr(), libc::MNT_DETACH))?;
            libc::rmdir(old_abs.as_ptr());
            check(libc::mount(
                c"proc".as_ptr(),
                c"/proc".as_ptr(),
                c"proc".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                std::ptr::null(),
            ))?;
            enter(&prepared)
        });
    }
    command.spawn()
}

/// How an exec's standard streams are wired.
pub enum Stdios {
    /// A PTY's slave on all three; the agent holds the master.
    Pty(std::os::fd::OwnedFd),
    Pipes { stdin: bool, stdout: Output, stderr: Output },
}

/// A pipe, both ends close-on-exec: (read, write).
fn pipe() -> io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd;
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two descriptors we then own.
    check(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    // SAFETY: fresh descriptors.
    Ok(unsafe { (std::os::fd::OwnedFd::from_raw_fd(fds[0]), std::os::fd::OwnedFd::from_raw_fd(fds[1])) })
}

/// Starts `process` in the workload's mount namespace (`mnt`, the
/// entrypoint's) and PID namespace (this thread's children's), in a
/// session of its own so a signal reaches its whole group. With stderr
/// combined, both streams share one pipe, whose read end is returned.
pub fn spawn_exec(process: &Process, mnt: RawFd, stdios: Stdios) -> io::Result<(Child, Option<std::os::fd::OwnedFd>)> {
    let mut command = Command::new(&process.argv[0]);
    let tty = matches!(stdios, Stdios::Pty(_));
    let prepared = prepare(&mut command, process, tty)?;
    let mut combined = None;
    match stdios {
        Stdios::Pty(slave) => {
            command.stdin(Stdio::from(slave.try_clone()?));
            command.stdout(Stdio::from(slave.try_clone()?));
            command.stderr(Stdio::from(slave));
        }
        Stdios::Pipes { stdin, stdout, stderr } => {
            command.stdin(if stdin { Stdio::piped() } else { Stdio::null() });
            match (stdout, stderr) {
                (Output::Pipe, Output::Combined) => {
                    let (r, w) = pipe()?;
                    command.stdout(Stdio::from(w.try_clone()?)).stderr(Stdio::from(w));
                    combined = Some(r);
                }
                (out, err) => {
                    let s = |o: Output| if o == Output::Pipe { Stdio::piped() } else { Stdio::null() };
                    command.stdout(s(out)).stderr(s(err));
                }
            }
        }
    }
    // SAFETY: system calls only, on prepared values, after fork.
    unsafe {
        command.pre_exec(move || {
            check(libc::setsid())?;
            if tty {
                check(libc::ioctl(0, libc::TIOCSCTTY as _, 0))?;
            }
            check(libc::setns(mnt, libc::CLONE_NEWNS))?;
            enter(&prepared)
        });
    }
    command.kill_on_drop(true);
    Ok((command.spawn()?, combined))
}

/// A new PTY at `rows` by `cols`: (master, slave), the master non-blocking.
pub fn openpty(rows: u16, cols: u16) -> io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd;
    let (mut master, mut slave) = (0, 0);
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: openpty writes two descriptors; the window size is borrowed.
    check(unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), &ws) })?;
    // SAFETY: fresh descriptors we own.
    let (master, slave) = unsafe { (std::os::fd::OwnedFd::from_raw_fd(master), std::os::fd::OwnedFd::from_raw_fd(slave)) };
    // SAFETY: fcntl on our own descriptors.
    unsafe {
        let fl = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        check(libc::fcntl(master.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK))?;
        check(libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC))?;
        check(libc::fcntl(slave.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC))?;
    }
    Ok((master, slave))
}

pub fn resize(master: RawFd, rows: u16, cols: u16) -> io::Result<()> {
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCSWINSZ reads a borrowed winsize.
    check(unsafe { libc::ioctl(master, libc::TIOCSWINSZ as _, &ws) })
}
