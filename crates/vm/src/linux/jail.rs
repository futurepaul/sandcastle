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
pub fn run(config_path: &Path, settings: &Settings, uid: u32, cgroup: Option<&Path>, payload: Payload) -> Result<i32, JailerError> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(JailerError::NotRoot);
    }
    // Into the VM's cgroup before the fork, so the VM is born in it.
    if let Some(cg) = cgroup {
        let procs = cg.join("cgroup.procs");
        std::fs::write(&procs, std::process::id().to_string()).map_err(sys("joining the cgroup", &procs))?;
    }
    let t0 = std::time::Instant::now();
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
    // A stop (systemd's SIGTERM, a ^C, a hangup) must still hand the
    // VM's files back, so the parent takes those signals synchronously:
    // blocked here, waited for with the child's exit below, and answered
    // by killing the VM. The child unblocks them before it execs.
    // SAFETY: sigset operations on a local set, and sigprocmask.
    let (set, old) = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGCHLD] {
            libc::sigaddset(&mut set, sig);
        }
        check(libc::sigprocmask(libc::SIG_BLOCK, &set, &mut old)).map_err(sys("sigprocmask", "/"))?;
        (set, old)
    };
    // SAFETY: unshare with a namespace flag; this process is single-threaded.
    check(unsafe { libc::unshare(libc::CLONE_NEWPID) }).map_err(sys("unshare pid", "/"))?;
    // SAFETY: single-threaded, so the child may run arbitrary code before exec.
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        return Err(sys("fork", "/")(std::io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: restores the mask the jailer was started with.
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
        let e = child(&plan, &jail_root, &config.id, payload, t0);
        eprintln!("jailer child: {e}");
        // SAFETY: leave without running the parent's destructors twice.
        unsafe { libc::_exit(127) };
    }
    let mut status = 0;
    // Bounded by the child's life: each pass reaps it or takes one signal.
    loop {
        // SAFETY: waits on our own child without blocking.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            break;
        }
        if r == -1 {
            return Err(sys("waitpid", "/")(std::io::Error::last_os_error()));
        }
        // SAFETY: waits for one of the blocked signals.
        let sig = unsafe { libc::sigwaitinfo(&set, std::ptr::null_mut()) };
        if sig == libc::SIGTERM || sig == libc::SIGINT || sig == libc::SIGHUP {
            // SAFETY: kill(2) on our own child, PID 1 of its namespace, which
            // only SIGKILL reaches from here.
            unsafe { libc::kill(pid, libc::SIGKILL) };
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

fn child(plan: &Plan, jail_root: &Path, hostname: &str, payload: Payload, t0: std::time::Instant) -> JailerError {
    match child_inner(plan, jail_root, hostname, payload, t0) {
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

fn child_inner(plan: &Plan, jail_root: &Path, hostname: &str, payload: Payload, t0: std::time::Instant) -> Result<std::convert::Infallible, JailerError> {
    let flags = libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
    // SAFETY: unshare with namespace flags in a single-threaded child.
    check(unsafe { libc::unshare(flags) }).map_err(sys("unshare", "/"))?;
    mount(None, Path::new("/"), None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    super::net::loopback_up().map_err(sys("bringing up lo", "lo"))?;
    if let Some(tap) = &plan.tap {
        super::net::make_tap(tap, plan.uid, plan.gid).map_err(sys("creating the tap", tap))?;
        let gw = sandcastle_wire::egress::GATEWAY_ADDR.octets();
        super::net::set_address(tap, gw, sandcastle_wire::egress::PREFIX).map_err(sys("addressing the tap", tap))?;
        super::net::set_up(tap).map_err(sys("bringing up the tap", tap))?;
    }
    let t_net = t0.elapsed();
    if let Some(rules) = &plan.nft {
        // The namespace's own tables: nothing here touches the host's.
        use std::io::Write;
        let mut nft = std::process::Command::new("/usr/sbin/nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(sys("running nft", "/usr/sbin/nft"))?;
        nft.stdin.take().expect("piped").write_all(rules.as_bytes()).map_err(sys("writing the rules", "nft"))?;
        let status = nft.wait().map_err(sys("waiting for nft", "nft"))?;
        if !status.success() {
            return Err(JailerError::Sys { what: "nft", path: "-f -".into(), source: std::io::Error::other(format!("exited {status}")) });
        }
    }

    let t_nft = t0.elapsed();
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

    // Every capability out of the bounding set and the ambient set first,
    // so nothing exec'd later can regain one even through a file
    // capability; then the drop: groups, then gid, then uid.
    let last_cap: libc::c_ulong = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(40);
    // SAFETY: prctl with plain values; bounded by the kernel's last capability.
    unsafe {
        for cap in 0..=last_cap {
            check(libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0)).map_err(sys("dropping the bounding set", "/"))?;
        }
        check(libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)).map_err(sys("clearing ambient capabilities", "/"))?;
    }
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
    // The VM dies with its jailer: a jailer killed outright takes the
    // runner with it. Set after the drop, which clears it. (From inside the
    // new PID namespace the parent is outside, so getppid reads 0 and
    // cannot say whether it is still there.)
    // SAFETY: prctl with plain values.
    check(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) }).map_err(sys("pdeathsig", "/"))?;
    // The refusals now; the runner adds its allowlist as its first act,
    // once the exec this needs is done.
    super::seccomp::install(None).map_err(sys("seccomp", "/"))?;

    // Where the jail's time went, for the supervisor (the runner's stdout
    // is this process's).
    println!(
        "{{\"event\":\"jailed\",\"jail_us\":{},\"net_us\":{},\"nft_us\":{}}}",
        t0.elapsed().as_micros(),
        t_net.as_micros(),
        (t_nft - t_net).as_micros()
    );
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

/// Hands every file under the spike's run and data directories that a VM
/// uid still owns back to the node's user: what a jailer killed outright
/// (and so never able to) leaves behind. Never follows a link, and touches
/// only owners in the VM range.
pub fn restore(settings: &Settings) -> Result<u64, JailerError> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(JailerError::NotRoot);
    }
    settings.validate()?;
    let range = settings.uid_base..settings.uid_base + settings.uid_count;
    let mut stack: Vec<PathBuf> = ["vms", "data"].iter().map(|d| settings.state_root.join(d)).filter(|p| p.exists()).collect();
    let mut restored = 0u64;
    let mut visited = 0usize;
    // Bounded: a stack of directories, each visited once, at most
    // RESTORE_ENTRIES_MAX entries in all.
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(sys("reading", &dir))? {
            let entry = entry.map_err(sys("reading", &dir))?;
            visited += 1;
            if visited > RESTORE_ENTRIES_MAX {
                return Err(JailerError::Sys { what: "restore", path: dir.display().to_string(), source: std::io::Error::other("too many entries") });
            }
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).map_err(sys("stat", &path))?;
            if meta.is_dir() {
                stack.push(path.clone());
            }
            if range.contains(&std::os::unix::fs::MetadataExt::uid(&meta)) {
                chown(&path, settings.owner_uid, settings.owner_gid)?;
                restored += 1;
            }
        }
        let meta = std::fs::symlink_metadata(&dir).map_err(sys("stat", &dir))?;
        if range.contains(&std::os::unix::fs::MetadataExt::uid(&meta)) {
            chown(&dir, settings.owner_uid, settings.owner_gid)?;
            restored += 1;
        }
    }
    Ok(restored)
}

/// Entries `restore` walks before it refuses.
pub const RESTORE_ENTRIES_MAX: usize = 100_000;
