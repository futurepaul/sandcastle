//! The VM process's seccomp filters, two, stacked:
//!
//! - the jailer's, before it execs the runner: a denylist of what a VMM
//!   never needs and an escape would (namespaces, mounts, tracing, kernel
//!   modules, keys, BPF), new namespaces through `clone` refused, and
//!   `clone3` answered ENOSYS so the C library falls back to `clone`, whose
//!   flags a filter can read; everything else allowed, `execve` included;
//! - the runner's own, its first act: the same refusals and an allowlist
//!   of what libkrun and the runner call (gathered from every scenario on
//!   lat-6 in audit mode), with anything else, `execve` among it, killing
//!   the process, as Firecracker's does.

use std::io;

use crate::jail::SeccompMode;

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_LOG: u32 = 0x7ffc_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;
const OFFSET_ARG0_LOW: u32 = 16;
/// A BPF program's instructions, as the kernel limits them.
const INSTRUCTIONS_MAX: usize = 4096;

const NAMESPACE_FLAGS: u32 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWCGROUP) as u32;

/// Refused in every mode.
#[cfg(target_arch = "x86_64")]
pub const DENIED: &[libc::c_long] = &[
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_reboot,
    libc::SYS_acct,
    libc::SYS_iopl,
    libc::SYS_ioperm,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
    libc::SYS_adjtimex,
    libc::SYS_syslog,
    libc::SYS_quotactl,
    libc::SYS_userfaultfd,
    libc::SYS_fanotify_init,
    libc::SYS_lookup_dcookie,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_personality,
];

/// What libkrun, the runner, and the C library call.
#[cfg(target_arch = "x86_64")]
pub const ALLOWED: &[libc::c_long] = &[
    // Files and descriptors.
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_preadv,
    libc::SYS_pwritev,
    libc::SYS_preadv2,
    libc::SYS_pwritev2,
    libc::SYS_lseek,
    libc::SYS_close,
    libc::SYS_openat,
    libc::SYS_open,
    libc::SYS_fstat,
    libc::SYS_newfstatat,
    libc::SYS_stat,
    libc::SYS_lstat,
    libc::SYS_statx,
    libc::SYS_statfs,
    libc::SYS_fstatfs,
    libc::SYS_access,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_readlink,
    libc::SYS_readlinkat,
    libc::SYS_getcwd,
    libc::SYS_getdents64,
    libc::SYS_fcntl,
    libc::SYS_dup,
    libc::SYS_dup2,
    libc::SYS_dup3,
    libc::SYS_pipe2,
    libc::SYS_ioctl,
    libc::SYS_fallocate,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_sync_file_range,
    libc::SYS_ftruncate,
    libc::SYS_fadvise64,
    libc::SYS_flock,
    libc::SYS_unlink,
    libc::SYS_unlinkat,
    libc::SYS_rename,
    libc::SYS_renameat2,
    libc::SYS_close_range,
    libc::SYS_copy_file_range,
    // Memory.
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_mremap,
    libc::SYS_brk,
    libc::SYS_memfd_create,
    libc::SYS_mlock,
    libc::SYS_munlock,
    // Threads, time, signals.
    libc::SYS_clone,
    libc::SYS_futex,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
    libc::SYS_gettid,
    libc::SYS_getpid,
    libc::SYS_getppid,
    libc::SYS_tgkill,
    libc::SYS_tkill,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigtimedwait,
    libc::SYS_sigaltstack,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_sched_setaffinity,
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_clock_nanosleep,
    libc::SYS_nanosleep,
    libc::SYS_gettimeofday,
    libc::SYS_membarrier,
    libc::SYS_prctl,
    libc::SYS_arch_prctl,
    libc::SYS_set_tid_address,
    libc::SYS_prlimit64,
    libc::SYS_getrlimit,
    libc::SYS_getrusage,
    libc::SYS_uname,
    libc::SYS_sysinfo,
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_getresuid,
    libc::SYS_getresgid,
    libc::SYS_getrandom,
    // Waiting.
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_wait,
    libc::SYS_epoll_pwait,
    libc::SYS_epoll_pwait2,
    libc::SYS_eventfd2,
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_settime,
    libc::SYS_timerfd_gettime,
    libc::SYS_poll,
    libc::SYS_ppoll,
    libc::SYS_pselect6,
    libc::SYS_select,
    // Sockets: vsock's unix ports, the forwarder, the control socket.
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    libc::SYS_recvmsg,
    libc::SYS_sendmsg,
    libc::SYS_recvmmsg,
    libc::SYS_sendmmsg,
    libc::SYS_shutdown,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    // The runner's own end, and its exec of nothing else.
    libc::SYS_kill,
];

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// The program, built as data so its shape is tested on any host: the
/// jailer's (`None`: the refusals, then allow) or the runner's (the
/// refusals, the allowlist, then the mode's default).
pub fn program(mode: Option<SeccompMode>) -> Vec<libc::sock_filter> {
    let eperm = RET_ERRNO | libc::EPERM as u32;
    let enosys = RET_ERRNO | libc::ENOSYS as u32;
    let mut p = vec![
        stmt(LD_W_ABS, OFFSET_ARCH),
        jump(JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(RET_K, RET_KILL_PROCESS),
        stmt(LD_W_ABS, OFFSET_NR),
        jump(JSET_K, X32_SYSCALL_BIT, 0, 1),
        stmt(RET_K, enosys),
    ];
    for nr in DENIED {
        p.push(jump(JEQ_K, *nr as u32, 0, 1));
        p.push(stmt(RET_K, eperm));
    }
    p.push(jump(JEQ_K, libc::SYS_clone3 as u32, 0, 1));
    p.push(stmt(RET_K, enosys));
    // clone: allowed unless it asks for a namespace.
    p.push(jump(JEQ_K, libc::SYS_clone as u32, 0, 4));
    p.push(stmt(LD_W_ABS, OFFSET_ARG0_LOW));
    p.push(jump(JSET_K, NAMESPACE_FLAGS, 0, 1));
    p.push(stmt(RET_K, eperm));
    p.push(stmt(RET_K, RET_ALLOW));
    let Some(mode) = mode else {
        p.push(stmt(RET_K, RET_ALLOW));
        return p;
    };
    let allowed: Vec<_> = ALLOWED.iter().filter(|n| **n != libc::SYS_clone).collect();
    for nr in allowed {
        p.push(jump(JEQ_K, *nr as u32, 0, 1));
        p.push(stmt(RET_K, RET_ALLOW));
    }
    p.push(stmt(
        RET_K,
        match mode {
            SeccompMode::Audit => RET_LOG,
            SeccompMode::Enforce => RET_KILL_PROCESS,
        },
    ));
    assert!(p.len() <= INSTRUCTIONS_MAX);
    p
}

/// Installs the filter on this thread and every thread it makes; the
/// caller has set no-new-privileges.
pub fn install(mode: Option<SeccompMode>) -> io::Result<()> {
    install_program(&program(mode))
}

/// A program made before a fork, installed after it without allocating.
pub fn install_program(prog: &[libc::sock_filter]) -> io::Result<()> {
    let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_ptr() as *mut libc::sock_filter };
    // SAFETY: a valid program that outlives the call (the kernel copies it).
    let r = unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &fprog as *const libc::sock_fprog) };
    if r == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: every jump lands inside the program, every path ends in a
    // return, and the default is the mode's.
    #[test]
    fn jumps_land_inside() {
        for (mode, last) in [(None, RET_ALLOW), (Some(SeccompMode::Audit), RET_LOG), (Some(SeccompMode::Enforce), RET_KILL_PROCESS)] {
            let p = program(mode);
            for (i, ins) in p.iter().enumerate() {
                if ins.code == JEQ_K || ins.code == JSET_K {
                    assert!(i + 1 + (ins.jt as usize) < p.len());
                    assert!(i + 1 + (ins.jf as usize) < p.len());
                }
            }
            assert_eq!(p.last().map(|i| (i.code, i.k)), Some((RET_K, last)));
        }
    }

    // Goal: the runner's allowlist never admits execve, and the jailer's
    // filter does (it execs the runner).
    #[test]
    fn execve_only_before_the_runner() {
        assert!(!ALLOWED.contains(&libc::SYS_execve) && !ALLOWED.contains(&libc::SYS_execveat));
        let jailer = program(None);
        assert!(!jailer.iter().any(|i| i.code == JEQ_K && i.k == libc::SYS_execve as u32));
    }

    // Goal: nothing is both denied and allowed.
    #[test]
    fn lists_disjoint() {
        for d in DENIED {
            assert!(!ALLOWED.contains(d), "{d} is denied and allowed");
        }
    }
}
