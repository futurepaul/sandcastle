//! The jailer: the one privileged step (docs/krun-spike.md). Run as root,
//! it makes the VM's writable files the VM uid's, forks a child into new
//! PID, mount, network, IPC, and UTS namespaces, builds a root holding only
//! what the plan names, drops to the VM uid with no new privileges and a
//! seccomp filter, and execs the runner. The parent stays root only to
//! wait, then hands the VM's files back to the node's user.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use thiserror::Error;

use super::runner::{read_config, RunError};
use crate::jail::{self, inside, JailError, MountKind, Plan, Settings};

#[derive(Debug, Error)]
pub enum JailerError {
    #[error("the jailer runs as root")]
    NotRoot,
    #[error(transparent)]
    Config(#[from] RunError),
    #[error(transparent)]
    Plan(#[from] JailError),
    #[error("{what} {path}: {source}")]
    Sys { what: &'static str, path: String, source: std::io::Error },
}

fn sys(what: &'static str, path: impl AsRef<Path>) -> impl FnOnce(std::io::Error) -> JailerError {
    let path = path.as_ref().display().to_string();
    move |source| JailerError::Sys { what, path, source }
}

fn cstr(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).expect("plan paths have no NUL")
}

fn check(r: libc::c_int) -> std::io::Result<()> {
    if r == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// What the jail runs in place of libkrun.
pub enum Payload {
    /// The runner, booting the VM.
    Runner,
    /// The escape probe, checking the jail from inside it.
    Probe { must_not_reach: Vec<PathBuf> },
}

/// Runs `payload` jailed as `uid`; returns its exit status.
pub fn run(config_path: &Path, settings: &Settings, uid: u32, payload: Payload) -> Result<i32, JailerError> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(JailerError::NotRoot);
    }
    let config = read_config(config_path)?;
    let plan = jail::plan(&config, settings, uid)?;
    for p in &plan.owned {
        chown(p, plan.uid, plan.gid)?;
    }
    let jail_root = settings.state_root.join("jailroot");
    match std::fs::create_dir(&jail_root) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(sys("creating", &jail_root)(e)),
    }
    // SAFETY: unshare with a namespace flag; this process is single-threaded.
    check(unsafe { libc::unshare(libc::CLONE_NEWPID) }).map_err(sys("unshare pid", "/"))?;
    // SAFETY: single-threaded, so the child may run arbitrary code before exec.
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        return Err(sys("fork", "/")(std::io::Error::last_os_error()));
    }
    if pid == 0 {
        let e = child(&plan, &jail_root, &config.id, payload);
        eprintln!("jailer child: {e}");
        // SAFETY: leave without running the parent's destructors twice.
        unsafe { libc::_exit(127) };
    }
    let mut status = 0;
    // Bounded by the child's life: retried only when a signal interrupts.
    loop {
        // SAFETY: waits on our own child.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            break;
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(sys("waitpid", "/")(e));
        }
    }
    for p in &plan.owned {
        chown(p, settings.owner_uid, settings.owner_gid)?;
    }
    let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 128 + libc::WTERMSIG(status) };
    Ok(code)
}

fn chown(p: &Path, uid: u32, gid: u32) -> Result<(), JailerError> {
    let c = cstr(p);
    // SAFETY: a NUL-terminated path; lchown never follows a link the VM
    // could have planted.
    check(unsafe { libc::lchown(c.as_ptr(), uid, gid) }).map_err(sys("chown", p))
}

fn child(plan: &Plan, jail_root: &Path, hostname: &str, payload: Payload) -> JailerError {
    match child_inner(plan, jail_root, hostname, payload) {
        Ok(never) => match never {},
        Err(e) => e,
    }
}

fn mount(source: Option<&Path>, target: &Path, fstype: Option<&str>, flags: libc::c_ulong, data: Option<&str>) -> Result<(), JailerError> {
    let s = source.map(cstr);
    let t = cstr(target);
    let f = fstype.map(|f| CString::new(f).expect("no NUL"));
    let d = data.map(|d| CString::new(d).expect("no NUL"));
    // SAFETY: NUL-terminated strings or null, as mount(2) takes them.
    let r = unsafe {
        libc::mount(
            s.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            t.as_ptr(),
            f.as_ref().map_or(std::ptr::null(), |f| f.as_ptr()),
            flags,
            d.as_ref().map_or(std::ptr::null(), |d| d.as_ptr() as *const libc::c_void),
        )
    };
    check(r).map_err(sys("mount", target))
}

fn child_inner(plan: &Plan, jail_root: &Path, hostname: &str, payload: Payload) -> Result<std::convert::Infallible, JailerError> {
    let flags = libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
    // SAFETY: unshare with namespace flags in a single-threaded child.
    check(unsafe { libc::unshare(flags) }).map_err(sys("unshare", "/"))?;
    mount(None, Path::new("/"), None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    super::net::loopback_up().map_err(sys("bringing up lo", "lo"))?;
    if let Some(tap) = &plan.tap {
        super::net::make_tap(tap, plan.uid, plan.gid).map_err(sys("creating the tap", tap))?;
    }

    mount(Some(Path::new("tmpfs")), jail_root, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV, Some("size=16m,mode=0755"))?;
    for m in &plan.mounts {
        let target = jail_root.join(m.target.strip_prefix("/").expect("plan targets are absolute"));
        let parent = target.parent().expect("targets are below the root");
        std::fs::create_dir_all(parent).map_err(sys("mkdir", parent))?;
        if m.file {
            std::fs::File::create(&target).map_err(sys("creating a mount point", &target))?;
        } else {
            std::fs::create_dir_all(&target).map_err(sys("mkdir", &target))?;
        }
        mount(Some(&m.source), &target, None, libc::MS_BIND, None)?;
        let mut f = libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOSUID;
        match m.kind {
            MountKind::BindRo { exec } => {
                f |= libc::MS_RDONLY | libc::MS_NODEV;
                if !exec {
                    f |= libc::MS_NOEXEC;
                }
            }
            MountKind::BindRw => f |= libc::MS_NODEV | libc::MS_NOEXEC,
            MountKind::Device => f |= libc::MS_NOEXEC,
        }
        mount(None, &target, None, f, None)?;
    }
    for (link, to) in &plan.links {
        let at = jail_root.join(link.strip_prefix("/").expect("absolute"));
        std::os::unix::fs::symlink(to, &at).map_err(sys("symlink", &at))?;
    }
    let config_at = jail_root.join(inside::CONFIG.trim_start_matches('/'));
    let json = serde_json::to_vec_pretty(&plan.inside).expect("a config serializes");
    std::fs::write(&config_at, json).map_err(sys("writing", &config_at))?;
    let proc_at = jail_root.join("proc");
    std::fs::create_dir(&proc_at).map_err(sys("mkdir", &proc_at))?;
    let old = jail_root.join(".old");
    std::fs::create_dir(&old).map_err(sys("mkdir", &old))?;

    let (new_root, put_old) = (cstr(jail_root), cstr(&old));
    // SAFETY: pivot_root(2) with two NUL-terminated paths; the new root is
    // a mount point (the tmpfs), and the old one is below it.
    check(unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), put_old.as_ptr()) } as libc::c_int)
        .map_err(sys("pivot_root", jail_root))?;
    std::env::set_current_dir("/").map_err(sys("chdir", "/"))?;
    let old_inside = cstr(Path::new("/.old"));
    // SAFETY: a NUL-terminated path.
    check(unsafe { libc::umount2(old_inside.as_ptr(), libc::MNT_DETACH) }).map_err(sys("umount", "/.old"))?;
    std::fs::remove_dir("/.old").map_err(sys("rmdir", "/.old"))?;
    mount(Some(Path::new("proc")), Path::new("/proc"), Some("proc"), libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, None)?;
    mount(None, Path::new("/"), None, libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV, None)?;

    // SAFETY: sethostname with a borrowed buffer and its length.
    check(unsafe { libc::sethostname(hostname.as_ptr() as *const libc::c_char, hostname.len()) })
        .map_err(sys("sethostname", hostname))?;

    // The drop: groups, then gid, then uid; after it, no capability is left.
    // SAFETY: plain values and a borrowed array.
    unsafe {
        check(libc::setgroups(plan.groups.len(), plan.groups.as_ptr())).map_err(sys("setgroups", "/"))?;
        check(libc::setresgid(plan.gid, plan.gid, plan.gid)).map_err(sys("setresgid", "/"))?;
        check(libc::setresuid(plan.uid, plan.uid, plan.uid)).map_err(sys("setresuid", "/"))?;
        check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)).map_err(sys("no_new_privs", "/"))?;
        let core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        check(libc::setrlimit(libc::RLIMIT_CORE, &core)).map_err(sys("rlimit core", "/"))?;
        libc::umask(0);
    }
    // SAFETY: getuid has no preconditions.
    assert_eq!(unsafe { libc::getuid() }, plan.uid, "the drop holds");
    super::seccomp::install().map_err(sys("seccomp", "/"))?;

    let mut argv: Vec<CString> = vec![CString::new("sandcastle-vm").expect("no NUL")];
    match payload {
        Payload::Runner => {
            argv.push(CString::new("run").expect("no NUL"));
            argv.push(CString::new("--config").expect("no NUL"));
            argv.push(CString::new(inside::CONFIG).expect("no NUL"));
        }
        Payload::Probe { must_not_reach } => {
            argv.push(CString::new("probe").expect("no NUL"));
            for p in must_not_reach {
                argv.push(cstr(&p));
            }
        }
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let env = [CString::new("PATH=/krun/bin").expect("no NUL")];
    let env_ptrs = [env[0].as_ptr(), std::ptr::null()];
    let runner = cstr(Path::new(inside::RUNNER));
    // SAFETY: NUL-terminated argv and envp, each ending in null.
    unsafe { libc::execve(runner.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr()) };
    Err(sys("execve", inside::RUNNER)(std::io::Error::last_os_error()))
}
