//! In the home: its sealed bundle opened (docs/nitro-home.md, "Secrets").
//!
//!   nitro-home-guest wrapped                     # the bundle's wrapped key, base64
//!   nitro-home-guest open --key-file K --out D   # its files under D (new, 0700)
//!   nitro-home-guest ask --listen A --platform H --suffix S --cell C   # Caddy's on-demand check (ask.rs)
//!
//! The bundle is the workload's `HOME_SEALED` (the parent hands it over as
//! it came, sealed). The key file is what `nitro-key wake --wrapped …`
//! wrote (64 hex digits, on a tmpfs); it is removed once read, whatever
//! follows. Nothing here prints a value: `open` says how many files.

use std::path::Path;

use base64::Engine as _;
use sandcastle_nitro_home::{ask, files, sealed};

/// The front door's checks answered at once, at most.
const ASKS_MAX: usize = 32;

const ENV: &str = "HOME_SEALED";

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].as_str())
}

fn bundle() -> Result<String, String> {
    std::env::var(ENV).map_err(|_| format!("no {ENV}: the home's start carries its sealed bundle"))
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("wrapped") => {
            let w = sealed::wrapped(&bundle()?).map_err(|e| e.to_string())?;
            println!("{}", base64::engine::general_purpose::STANDARD.encode(w));
            Ok(())
        }
        Some("open") => {
            let key_file = flag(args, "--key-file").ok_or("--key-file")?;
            let out = flag(args, "--out").ok_or("--out")?;
            let hex_key = std::fs::read_to_string(key_file).map_err(|e| format!("{key_file}: {e}"));
            // the key goes from the disk as soon as it is read, read or not
            let _ = std::fs::remove_file(key_file);
            let key = hex::decode(hex_key?.trim()).map_err(|_| format!("{key_file}: not hex"))?;
            let f = sealed::open(&bundle()?, &key).map_err(|e| e.to_string())?;
            files::write_dir(Path::new(out), &f).map_err(|e| e.to_string())?;
            println!("{}", serde_json::json!({"opened": f.len()}));
            Ok(())
        }
        Some("ask") => {
            let listen = flag(args, "--listen").ok_or("--listen")?;
            let a = ask::Ask {
                platform: flag(args, "--platform").ok_or("--platform")?.into(),
                suffix: flag(args, "--suffix").ok_or("--suffix")?.into(),
                cell: flag(args, "--cell").ok_or("--cell")?.parse().map_err(|_| "--cell: an address")?,
            };
            let listener = std::net::TcpListener::bind(listen).map_err(|e| format!("{listen}: {e}"))?;
            let live = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            // Unbounded by design: it answers for the home's life, at most
            // ASKS_MAX at once.
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                if live.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= ASKS_MAX {
                    live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    continue;
                }
                let (a, live) = (a.clone(), live.clone());
                std::thread::spawn(move || {
                    let _ = ask::answer(&a, conn);
                    live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                });
            }
            Ok(())
        }
        _ => Err("usage: nitro-home-guest wrapped | open --key-file <file> --out <dir> | ask --listen <addr> --platform <host> --suffix <suffix> --cell <addr>".into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("nitro-home-guest: {e}");
        std::process::exit(1);
    }
}
