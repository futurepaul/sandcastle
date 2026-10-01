//! A process and socket timeline from inside a guest, for `hermes-trace`:
//! every pid seen (its start from `/proc/<pid>/stat`, at CLK_TCK's
//! resolution, its parent and argv), when it was last seen and its CPU
//! then; each TCP port the moment it first listens; the machine's CPU and
//! its disks' reads every 100 ms. Times are the guest's boot clock, in ms.
//! Linked static (Cargo.toml) and copied in.
//!
//!   sandcastle-snoop <total_ms> <interval_us>

#[cfg(target_os = "linux")]
fn main() {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("sandcastle-snoop reads a Linux guest's /proc");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Write;
    use std::time::Duration;

    /// Pids above this are not followed; a guest's stay far below it.
    const PIDS_MAX: usize = 1 << 15;
    const MACHINE_EVERY_MS: f64 = 100.0;

    fn now_ms() -> f64 {
        let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: clock_gettime(2) writes the timespec it is given.
        let r = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) };
        assert_eq!(r, 0, "CLOCK_BOOTTIME is always there");
        t.tv_sec as f64 * 1e3 + t.tv_nsec as f64 / 1e6
    }

    struct Stat {
        comm: String,
        ppid: u32,
        cpu_ms: f64,
        start_ms: f64,
    }

    fn stat_of(pid: usize, tck: f64) -> Option<Stat> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let (l, r) = (s.find('(')?, s.rfind(')')?);
        // Fields after the comm: 3 state, 4 ppid, ... 14 utime, 15 stime, 22 starttime.
        let f: Vec<&str> = s[r + 2..].split(' ').collect();
        let field = |n: usize| f.get(n - 3).and_then(|v| v.parse::<f64>().ok());
        Some(Stat {
            comm: s[l + 1..r].to_string(),
            ppid: field(4)? as u32,
            cpu_ms: (field(14)? + field(15)?) * 1000.0 / tck,
            start_ms: field(22)? * 1000.0 / tck,
        })
    }

    fn argv_of(pid: usize) -> String {
        let mut b = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        b.truncate(300);
        String::from_utf8_lossy(&b).replace('\0', " ").trim_end().to_string()
    }

    fn ports(out: &mut impl Write, t: f64, file: &str, listening: &mut [bool]) {
        let Ok(s) = std::fs::read_to_string(file) else { return };
        for line in s.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (Some(local), Some(st)) = (f.get(1), f.get(3)) else { continue };
            let Some((addr, port)) = local.rsplit_once(':') else { continue };
            let Ok(port) = u16::from_str_radix(port, 16) else { continue };
            if *st == "0A" && !listening[port as usize] {
                listening[port as usize] = true;
                let _ = writeln!(out, "listen {t:.1} port {port} {}", if addr.len() > 8 { "v6" } else { addr });
            }
        }
    }

    fn machine(out: &mut impl Write, t: f64) {
        if let Ok(s) = std::fs::read_to_string("/proc/diskstats") {
            for line in s.lines() {
                let f: Vec<&str> = line.split_whitespace().collect();
                // name, reads completed, merged, sectors read, ms reading.
                if let [_, _, name, reads, _, sectors, ms, ..] = f[..] {
                    if name.len() == 3 && name.starts_with("vd") {
                        let _ = writeln!(out, "disk {t:.1} {name} reads {reads} sectors {sectors} ms {ms}");
                    }
                }
            }
        }
        if let Ok(s) = std::fs::read_to_string("/proc/stat") {
            if let Some(cpu) = s.lines().next() {
                let f: Vec<&str> = cpu.split_whitespace().collect();
                if let [_, u, ni, sy, idle, io, irq, sirq, ..] = f[..] {
                    let _ = writeln!(out, "cpu {t:.1} user {u} nice {ni} sys {sy} idle {idle} iowait {io} irq {irq} softirq {sirq}");
                }
            }
        }
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        let (Some(total), Some(interval)) = (args.get(1).and_then(|a| a.parse::<f64>().ok()), args.get(2).and_then(|a| a.parse::<u64>().ok())) else {
            eprintln!("sandcastle-snoop <total_ms> <interval_us>");
            std::process::exit(2);
        };
        // SAFETY: sysconf(3) has no preconditions.
        let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
        assert!(tck > 0.0);
        let me = std::process::id() as usize;
        let mut out = std::io::BufWriter::with_capacity(1 << 20, std::io::stdout().lock());
        // 0 unseen, 1 alive, 2 gone.
        let mut state = vec![0u8; PIDS_MAX];
        let mut seen = vec![false; PIDS_MAX];
        let mut cpu = vec![0f64; PIDS_MAX];
        let mut last = vec![0f64; PIDS_MAX];
        let mut listening = vec![false; 1 << 16];
        let t0 = now_ms();
        let mut next_machine = 0.0;
        let _ = writeln!(out, "begin {t0:.1} tck {tck} self {me}");
        // Bounded by `total`.
        while now_ms() - t0 < total {
            let t = now_ms();
            seen.fill(false);
            for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
                let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<usize>().ok()) else { continue };
                if pid == 0 || pid >= PIDS_MAX || pid == me {
                    continue;
                }
                let Some(s) = stat_of(pid, tck) else { continue };
                seen[pid] = true;
                cpu[pid] = s.cpu_ms;
                last[pid] = t;
                if state[pid] == 0 {
                    state[pid] = 1;
                    let argv = argv_of(pid);
                    let argv = if argv.is_empty() { format!("[{}]", s.comm) } else { argv };
                    let _ = writeln!(out, "new {t:.1} pid {pid} ppid {} start {:.0} comm {} cmd {argv}", s.ppid, s.start_ms, s.comm);
                }
            }
            for pid in 1..PIDS_MAX {
                if state[pid] == 1 && !seen[pid] {
                    state[pid] = 2;
                    let _ = writeln!(out, "exit {t:.1} pid {pid} last {:.1} cpu {:.0}", last[pid], cpu[pid]);
                }
            }
            ports(&mut out, t, "/proc/net/tcp", &mut listening);
            ports(&mut out, t, "/proc/net/tcp6", &mut listening);
            if t >= next_machine {
                machine(&mut out, t);
                next_machine = t + MACHINE_EVERY_MS;
            }
            std::thread::sleep(Duration::from_micros(interval));
        }
        let t = now_ms();
        for pid in 1..PIDS_MAX {
            if state[pid] == 1 {
                let _ = writeln!(out, "alive {t:.1} pid {pid} cpu {:.0}", cpu[pid]);
            }
        }
        machine(&mut out, t);
        let _ = writeln!(out, "end {t:.1}");
    }
}
