//! `sandcastle-guest`: a microVM's PID 1 (docs/krun-spike.md).

#[cfg(target_os = "linux")]
fn main() {
    sandcastle_guest::linux::init::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("sandcastle-guest is a Linux guest's init");
    std::process::exit(2);
}
