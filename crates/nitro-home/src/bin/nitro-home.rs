//! On the parent, as root: the home's sandbox (docs/nitro-home.md).
//!
//!   nitro-home up --conf <home.json>     # boot and hold it (a service's)
//!   nitro-home exec --dir <run dir> [--env K=V]… [--stdin <file>] -- <argv>…
//!
//! `up` holds the home until its workload exits (its code is this
//! process's) or until SIGTERM, which stops it gracefully. `exec` runs one
//! command in it through sandcastle's agent: what the parent can still do
//! (leak 2), kept for phase 1's operator.

#[cfg(target_os = "linux")]
fn run(args: &[String]) -> Result<i32, String> {
    use sandcastle_nitro_home::launch;
    let flag = |name: &str| args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone());
    match args.first().map(String::as_str) {
        Some("up") => {
            let conf = launch::Conf::load(std::path::Path::new(&flag("--conf").ok_or("--conf")?)).map_err(|e| e.0)?;
            match launch::up(&conf).map_err(|e| e.0)? {
                Some(code) => Ok(code),
                None => Ok(75),
            }
        }
        Some("exec") => {
            let dir = flag("--dir").ok_or("--dir")?;
            let at = args.iter().position(|a| a == "--").ok_or("-- <argv>")?;
            let env: Vec<String> = args[..at].windows(2).filter(|w| w[0] == "--env").map(|w| w[1].clone()).collect();
            let stdin = match flag("--stdin") {
                Some(f) => Some(std::fs::read(&f).map_err(|e| format!("{f}: {e}"))?),
                None => None,
            };
            let out = launch::exec(std::path::Path::new(&dir), args[at + 1..].to_vec(), env, stdin).map_err(|e| e.0)?;
            println!("{out}");
            Ok(out["code"].as_i64().unwrap_or(1) as i32)
        }
        _ => Err("usage: nitro-home up --conf <file> | exec --dir <dir> [--env K=V]… -- <argv>…".into()),
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_: &[String]) -> Result<i32, String> {
    Err("nitro-home runs on a Linux parent".into())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("nitro-home: {e}");
            std::process::exit(1);
        }
    }
}
