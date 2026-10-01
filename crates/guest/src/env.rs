//! A process's environment: what it asked for, plus the defaults a
//! container's processes expect when the image does not set them.

/// Docker's default, which images are built against.
pub const PATH_DEFAULT: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub fn environment(env: &[String], home: &str, hostname: &str, tty: bool) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(env.len() + 4);
    for e in env {
        if let Some((k, v)) = e.split_once('=') {
            // A later entry for the same key wins, as in a shell.
            out.retain(|(ok, _)| ok != k);
            out.push((k.to_string(), v.to_string()));
        }
    }
    let mut default = |k: &str, v: &str| {
        if !out.iter().any(|(ok, _)| ok == k) {
            out.push((k.to_string(), v.to_string()));
        }
    };
    default("PATH", PATH_DEFAULT);
    default("HOME", home);
    default("HOSTNAME", hostname);
    if tty {
        default("TERM", "xterm");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_fill_gaps_only() {
        let e = environment(&["PATH=/opt/bin".into(), "A=1".into(), "A=2".into()], "/root", "h", true);
        assert!(e.contains(&("PATH".into(), "/opt/bin".into())));
        assert!(e.contains(&("A".into(), "2".into())));
        assert_eq!(e.iter().filter(|(k, _)| k == "A").count(), 1);
        assert!(e.contains(&("HOME".into(), "/root".into())));
        assert!(e.contains(&("TERM".into(), "xterm".into())));
        let e = environment(&[], "/", "h", false);
        assert!(e.contains(&("PATH".into(), PATH_DEFAULT.into())));
        assert!(!e.iter().any(|(k, _)| k == "TERM"));
    }
}
