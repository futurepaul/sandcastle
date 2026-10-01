//! Who a process runs as: `uid`, `uid:gid`, or a name in the workload's
//! `/etc/passwd` (and, for `name:group`, its `/etc/group`), as OCI images
//! name their `User`.

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

pub const ROOT: User = User { uid: 0, gid: 0, home: String::new() };

/// Resolves `spec` against the image's `passwd` and `group` files' text.
pub fn resolve(spec: &str, passwd: &str, group: &str) -> Option<User> {
    let (user, grp) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    if user.is_empty() {
        return None;
    }
    let by_name = passwd.lines().filter_map(parse_passwd).find(|(name, ..)| *name == user);
    let (uid, mut gid, home) = match (user.parse::<u32>(), by_name) {
        (Ok(uid), _) => {
            let entry = passwd.lines().filter_map(parse_passwd).find(|(_, u, ..)| *u == uid);
            (uid, entry.as_ref().map_or(uid, |e| e.2), entry.map_or("/".to_string(), |e| e.3.to_string()))
        }
        (Err(_), Some((_, uid, gid, home))) => (uid, gid, home.to_string()),
        (Err(_), None) => return None,
    };
    if let Some(g) = grp {
        gid = match g.parse::<u32>() {
            Ok(n) => n,
            Err(_) => group
                .lines()
                .filter_map(|l| {
                    let mut f = l.split(':');
                    let name = f.next()?;
                    let _ = f.next()?;
                    let id = f.next()?.parse::<u32>().ok()?;
                    Some((name, id))
                })
                .find(|(name, _)| *name == g)?
                .1,
        };
    }
    Some(User { uid, gid, home: if home.is_empty() { "/".into() } else { home } })
}

fn parse_passwd(line: &str) -> Option<(&str, u32, u32, &str)> {
    let mut f = line.split(':');
    let name = f.next()?;
    let _ = f.next()?;
    let uid = f.next()?.parse().ok()?;
    let gid = f.next()?.parse().ok()?;
    let _ = f.next()?;
    let home = f.next()?;
    Some((name, uid, gid, home))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\nhermes:x:1000:1001::/home/hermes:/bin/bash\nbad line\n";
    const GROUP: &str = "root:x:0:\nhermes:x:1001:\nstaff:x:50:hermes\n";

    #[test]
    fn resolves() {
        assert_eq!(resolve("hermes", PASSWD, GROUP), Some(User { uid: 1000, gid: 1001, home: "/home/hermes".into() }));
        assert_eq!(resolve("0", PASSWD, GROUP), Some(User { uid: 0, gid: 0, home: "/root".into() }));
        assert_eq!(resolve("1234", PASSWD, GROUP), Some(User { uid: 1234, gid: 1234, home: "/".into() }));
        assert_eq!(resolve("hermes:staff", PASSWD, GROUP).map(|u| u.gid), Some(50));
        assert_eq!(resolve("1000:7", PASSWD, GROUP).map(|u| (u.uid, u.gid)), Some((1000, 7)));
    }

    #[test]
    fn refuses_unknown() {
        assert_eq!(resolve("nobody", PASSWD, GROUP), None);
        assert_eq!(resolve("hermes:nogroup", PASSWD, GROUP), None);
        assert_eq!(resolve("", PASSWD, GROUP), None);
        assert_eq!(resolve(":0", PASSWD, GROUP), None);
    }
}
