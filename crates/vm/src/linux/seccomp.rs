//! The VM process's seccomp filter: a denylist of what a VMM never needs
//! and an escape would (namespaces, mounts, tracing, kernel modules, keys,
//! BPF), plus new namespaces through `clone`, and `clone3` answered
//! ENOSYS so the C library falls back to `clone`, whose flags a filter can
//! read. An allowlist built from libkrun's observed calls is stronger; it
//! is the ledger's ("A sandcastle VM's seccomp filter is a denylist").

use std::io;

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
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

#[cfg(target_arch = "x86_64")]
const DENIED: &[libc::c_long] = &[
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

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// The program, built as data so its shape is tested on any host.
pub fn program() -> Vec<libc::sock_filter> {
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
    p.push(jump(JEQ_K, libc::SYS_clone as u32, 0, 3));
    p.push(stmt(LD_W_ABS, OFFSET_ARG0_LOW));
    p.push(jump(JSET_K, NAMESPACE_FLAGS, 0, 1));
    p.push(stmt(RET_K, eperm));
    p.push(stmt(RET_K, RET_ALLOW));
    assert!(p.len() <= INSTRUCTIONS_MAX);
    p
}

/// Installs the filter on this thread and every thread it makes; the
/// caller has set no-new-privileges.
pub fn install() -> io::Result<()> {
    let prog = program();
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

    // Goal: every jump lands inside the program and the program ends in a
    // return, so the kernel's verifier accepts it.
    #[test]
    fn jumps_land_inside() {
        let p = program();
        for (i, ins) in p.iter().enumerate() {
            if ins.code == JEQ_K || ins.code == JSET_K {
                assert!(i + 1 + (ins.jt as usize) < p.len());
                assert!(i + 1 + (ins.jf as usize) < p.len());
            }
        }
        assert_eq!(p.last().map(|i| (i.code, i.k)), Some((RET_K, RET_ALLOW)));
    }
}
