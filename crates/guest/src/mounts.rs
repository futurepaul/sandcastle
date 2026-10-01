//! What the guest mounts, as data: the basics the init needs, the
//! workload's root (the image read-only under a fresh scratch disk's
//! overlay, with `/data` on top), and the build target.

use sandcastle_wire::disks;

/// Where the init keeps the workload's layers, on its own tmpfs.
pub const RUN: &str = "/run/sc";
pub const LOWER: &str = "/run/sc/lower";
pub const SCRATCH: &str = "/run/sc/scratch";
pub const UPPER: &str = "/run/sc/scratch/upper";
pub const WORK: &str = "/run/sc/scratch/work";
pub const ROOT: &str = "/run/sc/root";
pub const TARGET: &str = "/run/sc/target";
/// Where Cloudflare's containers find the interception CA.
pub const CA_PATH: &str = "etc/cloudflare/certs/cloudflare-containers-ca.crt";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    pub read_only: bool,
    pub nosuid: bool,
    pub nodev: bool,
    pub noexec: bool,
    pub bind: bool,
    pub recursive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub source: String,
    pub target: String,
    pub fstype: Option<&'static str>,
    pub flags: Flags,
    pub data: Option<String>,
    /// Already mounted is fine (devtmpfs, which the kernel may mount).
    pub may_exist: bool,
}

fn m(source: &str, target: &str, fstype: &'static str, flags: Flags, data: Option<&str>) -> Mount {
    Mount { source: source.into(), target: target.into(), fstype: Some(fstype), flags, data: data.map(Into::into), may_exist: false }
}

const NOSUID_NODEV_NOEXEC: Flags = Flags { read_only: false, nosuid: true, nodev: true, noexec: true, bind: false, recursive: false };
const NOSUID_NODEV: Flags = Flags { read_only: false, nosuid: true, nodev: true, noexec: false, bind: false, recursive: false };

/// The init's own: proc, sys, dev, ptys, shared memory, and its tmpfs.
pub fn basics() -> Vec<Mount> {
    let mut dev = m("devtmpfs", "/dev", "devtmpfs", Flags { nosuid: true, ..Flags::default() }, Some("mode=0755"));
    dev.may_exist = true;
    vec![
        m("proc", "/proc", "proc", NOSUID_NODEV_NOEXEC, None),
        m("sysfs", "/sys", "sysfs", NOSUID_NODEV_NOEXEC, None),
        dev,
        m("devpts", "/dev/pts", "devpts", Flags { nosuid: true, noexec: true, ..Flags::default() }, Some("gid=5,mode=620,ptmxmode=666")),
        m("tmpfs", "/dev/shm", "tmpfs", NOSUID_NODEV, Some("mode=1777")),
        m("tmpfs", "/run", "tmpfs", NOSUID_NODEV, Some("mode=0755")),
    ]
}

/// Directories made before `basics` (they are on the read-only boot disk)
/// and after it (on the init's tmpfs).
pub fn dirs_after_basics(build: bool) -> Vec<&'static str> {
    if build {
        vec![RUN, TARGET]
    } else {
        vec![RUN, LOWER, SCRATCH, ROOT]
    }
}

/// The workload's root: the image read-only, a fresh scratch disk as the
/// overlay's upper layer, so every start begins from the image exactly.
pub fn run_root() -> Vec<Mount> {
    vec![
        m(disks::IMAGE, LOWER, "ext4", Flags { read_only: true, nodev: true, ..Flags::default() }, Some("noload")),
        m(disks::SCRATCH, SCRATCH, "ext4", Flags::default(), None),
    ]
}

/// The overlay, once the scratch disk's `upper` and `work` exist.
pub fn overlay() -> Mount {
    let data = format!("lowerdir={LOWER},upperdir={UPPER},workdir={WORK}");
    m("overlay", ROOT, "overlay", Flags::default(), Some(&data))
}

/// `/data`, on the computer's own disk, over the root.
pub fn data() -> Mount {
    m(disks::DATA, &format!("{ROOT}/data"), "ext4", Flags { nodev: true, ..Flags::default() }, None)
}

pub fn build_target() -> Mount {
    m(disks::TARGET, TARGET, "ext4", Flags::default(), None)
}

/// Inside the entrypoint's mount namespace, before it pivots into the
/// root: the init's `/dev` (so a PTY the agent opens is the workload's
/// too) and a fresh sysfs, read-only.
pub fn workload() -> Vec<Mount> {
    vec![
        Mount {
            source: "/dev".into(),
            target: format!("{ROOT}/dev"),
            fstype: None,
            flags: Flags { bind: true, recursive: true, ..Flags::default() },
            data: None,
            may_exist: false,
        },
        m("sysfs", &format!("{ROOT}/sys"), "sysfs", Flags { read_only: true, ..NOSUID_NODEV_NOEXEC }, None),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: the image is never mounted writable, and the overlay's layers
    // are the paths the plan mounts.
    #[test]
    fn image_read_only() {
        let r = run_root();
        assert_eq!(r[0].source, disks::IMAGE);
        assert!(r[0].flags.read_only);
        assert!(!r[1].flags.read_only);
        let o = overlay();
        let data = o.data.unwrap();
        assert!(data.contains(LOWER) && data.contains(UPPER) && data.contains(WORK));
        assert!(UPPER.starts_with(SCRATCH) && WORK.starts_with(SCRATCH));
    }

    #[test]
    fn workload_under_root() {
        for m in workload() {
            assert!(m.target.starts_with(ROOT));
        }
        assert!(data().target.starts_with(ROOT));
        assert!(basics().iter().any(|m| m.target == "/dev" && m.may_exist));
    }
}
