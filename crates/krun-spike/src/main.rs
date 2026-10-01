//! `sandcastle-krun-spike`: the libkrun spike's driver (docs/krun-spike.md).
//! Each scenario prints its evidence as one JSON object and keeps a copy
//! in `results/`. A lower-rung diagnostic: its numbers are the engine's on
//! this node, not the product's.

#[cfg(target_os = "linux")]
mod image;
#[cfg(target_os = "linux")]
mod launch;
#[cfg(target_os = "linux")]
mod layout;
#[cfg(target_os = "linux")]
mod scenarios;

use std::process::ExitCode;

#[derive(Debug)]
pub struct Error(pub String);

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl Error {
    pub fn msg(s: impl Into<String>) -> Error {
        Error(s.into())
    }
    pub fn io(what: &'static str) -> impl FnOnce(std::io::Error) -> Error {
        move |e| Error(format!("{what}: {e}"))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Median, minimum, and maximum of `samples`, in their unit.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn stats(samples: &[f64]) -> serde_json::Value {
    assert!(!samples.is_empty());
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    let n = s.len();
    let median = if n % 2 == 1 { s[n / 2] } else { (s[n / 2 - 1] + s[n / 2]) / 2.0 };
    let round = |x: f64| (x * 1000.0).round() / 1000.0;
    serde_json::json!({"n": n, "median": round(median), "min": round(s[0]), "max": round(s[n - 1])})
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run(&args)
}

#[cfg(target_os = "linux")]
fn run(args: &[String]) -> ExitCode {
    let layout = layout::Layout::from_env();
    match scenarios::dispatch(&layout, args) {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).expect("serializes"));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sandcastle-krun-spike: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_: &[String]) -> ExitCode {
    eprintln!("the spike's driver runs on its Linux node");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    #[test]
    fn stats_median() {
        let s = super::stats(&[3.0, 1.0, 2.0]);
        assert_eq!(s["median"], 2.0);
        assert_eq!(s["min"], 1.0);
        let s = super::stats(&[1.0, 2.0, 3.0, 4.0]);
        assert_eq!(s["median"], 2.5);
    }
}
