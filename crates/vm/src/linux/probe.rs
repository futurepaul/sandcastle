//! The escape probe (acceptance 7): run by the jailer in place of the
//! runner, with the same namespaces, mounts, uid, and filter, it tries
//! what a guest that escaped into its VMM would try, and prints what it
//! found as JSON. Every check is expected to fail; the driver compares.
//! Its arguments are what must stay out of reach: paths, and `tcp:ip:port`
//! addresses (the node's own services).

use std::ffi::CString;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

fn errno_of(r: libc::c_long) -> Value {
    if r == -1 {
        json!(std::io::Error::last_os_error().to_string())
    } else {
        json!("allowed")
    }
}

fn reach(p: &Path) -> Value {
    let read = std::fs::read_dir(p).map(|_| "listed").or_else(|_| std::fs::read(p).map(|_| "read"));
    match read {
        Ok(how) => json!(how),
        Err(e) => json!(e.to_string()),
    }
}

/// The runner's allowlist, enforced in a child that then makes one call:
/// how the child ended.
fn under_allowlist(prog: &[libc::sock_filter], call: impl FnOnce()) -> Value {
    // SAFETY: fork(2) in the single-threaded probe; the child installs a
    // program made before the fork, makes its call, and `_exit`s.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        if super::seccomp::install_program(prog).is_err() {
            // SAFETY: ends the child.
            unsafe { libc::_exit(2) };
        }
        call();
        // SAFETY: ends the child.
        unsafe { libc::_exit(0) };
    }
    if pid < 0 {
        return json!(std::io::Error::last_os_error().to_string());
    }
    let mut status = 0;
    // SAFETY: waits for our own child.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFSIGNALED(status) {
        json!(format!("signal {}", libc::WTERMSIG(status)))
    } else {
        json!(format!("exit {}", libc::WEXITSTATUS(status)))
    }
}

pub fn run(must_not_reach: &[String]) -> i32 {
    // SAFETY: getres*id write to locals.
    let (mut ruid, mut euid, mut suid, mut rgid, mut egid, mut sgid) = (0, 0, 0, 0, 0, 0);
    unsafe {
        libc::getresuid(&mut ruid, &mut euid, &mut suid);
        libc::getresgid(&mut rgid, &mut egid, &mut sgid);
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| status.lines().find(|l| l.starts_with(name)).map(|l| l[name.len()..].trim().to_string());
    let pids: Vec<String> = std::fs::read_dir("/proc")
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.bytes().all(|b| b.is_ascii_digit()))
                .collect()
        })
        .unwrap_or_default();

    let connect = |a: &str| match a.parse::<SocketAddr>() {
        Ok(addr) => match TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
            Ok(_) => json!("connected"),
            Err(e) => json!(e.to_string()),
        },
        Err(_) => json!("not an address"),
    };
    let mut reached = serde_json::Map::new();
    for p in must_not_reach {
        let found = match p.strip_prefix("tcp:") {
            Some(addr) => connect(addr),
            None => reach(Path::new(p)),
        };
        reached.insert(p.clone(), found);
    }
    let tmp = CString::new("/").expect("no NUL");
    // SAFETY: each call is made to be refused; arguments are valid.
    let syscalls = unsafe {
        json!({
            "mount": errno_of(libc::mount(tmp.as_ptr(), tmp.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) as libc::c_long),
            "unshare_user": errno_of(libc::unshare(libc::CLONE_NEWUSER) as libc::c_long),
            "ptrace_traceme": errno_of(libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0)),
            "setuid_0": errno_of(libc::setuid(0) as libc::c_long),
            "chroot": errno_of(libc::chroot(tmp.as_ptr()) as libc::c_long),
            "bpf": errno_of(libc::syscall(libc::SYS_bpf, 0, 0, 0)),
            "clone3": errno_of(libc::syscall(libc::SYS_clone3, 0, 0)),
        })
    };
    let write_root = std::fs::write("/escape", b"x").map(|_| "written").map_err(|e| e.to_string());
    let write_lib = std::fs::OpenOptions::new()
        .write(true)
        .open(super::super::jail::inside::LIB.to_string() + "/libkrun.so")
        .map(|_| "opened for writing")
        .map_err(|e| e.to_string());
    let write_boot = std::fs::OpenOptions::new()
        .write(true)
        .open("/disks/boot.ext4")
        .map(|_| "opened for writing")
        .map_err(|e| e.to_string());
    let kvm = std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").map(|_| "opened").map_err(|e| e.to_string());
    let host_files = ["/home", "/etc/shadow", "/var/lib", "/root", "/sys", "/dev/zvol", "/tank"];
    let mut host = serde_json::Map::new();
    for p in host_files {
        host.insert(p.into(), reach(Path::new(p)));
    }
    // The runner's own filter: a call it allows, and execve, which no
    // runner makes (SIGSYS is 31).
    let allowlist = super::seccomp::program(Some(crate::jail::SeccompMode::Enforce));
    let sh = CString::new("/bin/sh").expect("no NUL");
    let allowlist = json!({
        "getpid": under_allowlist(&allowlist, || {
            // SAFETY: getpid(2) has no arguments.
            unsafe { libc::getpid() };
        }),
        "execve": under_allowlist(&allowlist, || {
            // SAFETY: the filter ends the process at the call; the
            // arguments are valid either way.
            unsafe { libc::syscall(libc::SYS_execve, sh.as_ptr(), std::ptr::null::<*const libc::c_char>(), std::ptr::null::<*const libc::c_char>()) };
        }),
    });
    let mut root = Vec::new();
    if let Ok(d) = std::fs::read_dir("/") {
        for e in d.flatten() {
            root.push(e.file_name().as_bytes().iter().map(|b| *b as char).collect::<String>());
        }
    }
    root.sort();
    let report = json!({
        "uid": [ruid, euid, suid],
        "gid": [rgid, egid, sgid],
        "groups": field("Groups:"),
        "cap_eff": field("CapEff:"),
        "cap_bnd": field("CapBnd:"),
        "no_new_privs": field("NoNewPrivs:"),
        "seccomp": field("Seccomp:"),
        "visible_pids": pids,
        "root_entries": root,
        "must_not_reach": reached,
        "host_paths": host,
        "syscalls": syscalls,
        "allowlist": allowlist,
        "write_root": format!("{write_root:?}"),
        "write_libkrun": format!("{write_lib:?}"),
        "write_boot_disk": format!("{write_boot:?}"),
        "open_kvm": format!("{kvm:?}"),
        "connect_public": connect("1.1.1.1:443"),
    });
    println!("{report}");
    0
}
