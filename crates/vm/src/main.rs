//! `sandcastle-vm`: the runner, the jailer, and the escape probe, one
//! binary so the jail binds one file.
//!
//! - `run --config <path>`: boot the VM the config describes, here.
//! - `jail --config <path> --settings <path> --uid <uid> [--probe <what>...]`:
//!   as root, jail the runner (or the probe) as `uid` and wait for it.
//! - `probe <what>...`: what the jailer runs with `--probe`.
//! - `restore --settings <path>`: as root, hand back to the node's user any
//!   VM file a jailer killed outright left owned by a VM uid.

use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: sandcastle-vm run --config <path> | jail --config <path> --settings <path> --uid <uid> [--probe <what>...] | probe <what>... | restore --settings <path>");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else { return usage() };
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    match cmd.as_str() {
        "run" => {
            let Some(config) = flag("--config") else { return usage() };
            run(PathBuf::from(config))
        }
        "jail" => {
            let (Some(config), Some(settings), Some(uid)) = (flag("--config"), flag("--settings"), flag("--uid")) else {
                return usage();
            };
            let Ok(uid) = uid.parse::<u32>() else { return usage() };
            let probe = args.iter().position(|a| a == "--probe").map(|i| args[i + 1..].to_vec());
            jail(PathBuf::from(config), PathBuf::from(settings), uid, probe)
        }
        "probe" => probe(&args[1..]),
        "restore" => {
            let Some(settings) = flag("--settings") else { return usage() };
            restore(PathBuf::from(settings))
        }
        _ => usage(),
    }
}

#[cfg(target_os = "linux")]
fn run(config: PathBuf) -> ExitCode {
    match sandcastle_vm::linux::runner::run(&config) {
        Ok(never) => match never {},
        Err(e) => {
            eprintln!("sandcastle-vm run: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn jail(config: PathBuf, settings: PathBuf, uid: u32, probe: Option<Vec<String>>) -> ExitCode {
    use sandcastle_vm::linux::jail::{run, Payload};
    let settings: sandcastle_vm::jail::Settings = match std::fs::read(&settings)
        .map_err(|e| e.to_string())
        .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sandcastle-vm jail: settings: {e}");
            return ExitCode::FAILURE;
        }
    };
    let payload = match probe {
        Some(what) => Payload::Probe { must_not_reach: what.into_iter().map(PathBuf::from).collect() },
        None => Payload::Runner,
    };
    match run(&config, &settings, uid, payload) {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("sandcastle-vm jail: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn restore(settings: PathBuf) -> ExitCode {
    let settings: sandcastle_vm::jail::Settings = match std::fs::read(&settings)
        .map_err(|e| e.to_string())
        .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sandcastle-vm restore: settings: {e}");
            return ExitCode::FAILURE;
        }
    };
    match sandcastle_vm::linux::jail::restore(&settings) {
        Ok(n) => {
            println!("{{\"restored\":{n}}}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sandcastle-vm restore: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn restore(_: PathBuf) -> ExitCode {
    eprintln!("sandcastle-vm restores on Linux only");
    ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn probe(what: &[String]) -> ExitCode {
    ExitCode::from(sandcastle_vm::linux::probe::run(what) as u8)
}

#[cfg(not(target_os = "linux"))]
fn run(_: PathBuf) -> ExitCode {
    eprintln!("sandcastle-vm runs VMs on Linux only");
    ExitCode::FAILURE
}

#[cfg(not(target_os = "linux"))]
fn jail(_: PathBuf, _: PathBuf, _: u32, _: Option<Vec<String>>) -> ExitCode {
    eprintln!("sandcastle-vm jails on Linux only");
    ExitCode::FAILURE
}

#[cfg(not(target_os = "linux"))]
fn probe(_: &[String]) -> ExitCode {
    eprintln!("sandcastle-vm probes on Linux only");
    ExitCode::FAILURE
}
