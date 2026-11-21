//! On the operator's machine: the home's secrets sealed (docs/nitro-home.md,
//! "Secrets").
//!
//!   nitro-home-seal --dir <secrets> --kms-key <id> --out <bundle>
//!                   [--profile finite] [--region us-east-2]
//!
//! Every file under `--dir` (owner-only, as is each directory) is sealed
//! under a fresh key K with AES-256-GCM (sealed.rs). K goes to KMS's
//! `Encrypt` under the home's key through the AWS CLI's standard input,
//! never a file or an argument, and is dropped; KMS releases it again only
//! to the home's image (the key's policy names its PCR0). The bundle is
//! written owner-only. Nothing here prints a value or K.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

use base64::Engine as _;
use ring::rand::{SecureRandom as _, SystemRandom};
use sandcastle_nitro_home::{files, sealed};

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].as_str())
}

/// KMS's ciphertext of `key` under `kms_key`, by the AWS CLI.
fn kms_encrypt(key: &[u8], kms_key: &str, profile: &str, region: &str) -> Result<Vec<u8>, String> {
    let mut child = Command::new("aws")
        .args(["--profile", profile, "--region", region, "kms", "encrypt", "--key-id", kms_key, "--plaintext", "fileb:///dev/stdin", "--query", "CiphertextBlob", "--output", "text"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("the AWS CLI: {e}"))?;
    child.stdin.take().expect("piped").write_all(key).map_err(|e| format!("the AWS CLI's input: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("the AWS CLI: {e}"))?;
    if !out.status.success() {
        return Err(format!("KMS Encrypt: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    base64::engine::general_purpose::STANDARD.decode(String::from_utf8_lossy(&out.stdout).trim()).map_err(|_| "KMS answered no base64 ciphertext".into())
}

fn run(args: &[String]) -> Result<(), String> {
    let dir = flag(args, "--dir").ok_or("--dir")?;
    let kms_key = flag(args, "--kms-key").ok_or("--kms-key")?;
    let out = flag(args, "--out").ok_or("--out")?;
    let profile = flag(args, "--profile").unwrap_or("finite");
    let region = flag(args, "--region").unwrap_or("us-east-2");
    let f = files::read_dir(Path::new(dir)).map_err(|e| e.to_string())?;
    let rng = SystemRandom::new();
    let mut key = [0u8; sealed::KEY_BYTES];
    let mut nonce = [0u8; 12];
    rng.fill(&mut key).map_err(|_| "the system's randomness")?;
    rng.fill(&mut nonce).map_err(|_| "the system's randomness")?;
    let wrapped = kms_encrypt(&key, kms_key, profile, region);
    let bundle = wrapped.and_then(|w| sealed::seal(&f, &key, nonce, &w).map_err(|e| e.to_string()));
    key.fill(0);
    let bundle = bundle?;
    let tmp = format!("{out}.new");
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| format!("{tmp}: {e}"))?;
    file.write_all(bundle.as_bytes()).and_then(|_| file.write_all(b"\n")).and_then(|_| file.sync_all()).map_err(|e| format!("{tmp}: {e}"))?;
    std::fs::rename(&tmp, out).map_err(|e| format!("{out}: {e}"))?;
    let names: Vec<&String> = f.keys().collect();
    println!("{}", serde_json::json!({"sealed": names, "bytes": bundle.len(), "out": out}));
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("nitro-home-seal: {e}");
        std::process::exit(1);
    }
}
