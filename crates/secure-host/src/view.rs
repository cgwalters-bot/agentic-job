//! A root-installed mount view, shared by run0 and the user's manager.
//!
//! Stop untrusted code altering host files that happen to be world writable,
//! without having to inventory an image whose contents change on every run.

use anyhow::{Result, ensure};

use crate::host::User;

/// These are system-service properties, not properties delegated to the user
/// manager. Do not add NoNewPrivileges, PrivateUsers or PrivateDevices: they
/// would break subordinate-id helpers or KVM.
pub fn properties(user: &User) -> Result<Vec<String>> {
    let home = user.home.to_str().unwrap_or_default();
    ensure!(
        home.starts_with('/')
            && home != "/"
            && home
                .split('/')
                .skip(1)
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && !home.contains(char::is_whitespace)
            && !home.contains(['%', '\\', '"', '\n']),
        "sandbox home {home:?} cannot be represented safely in systemd path properties"
    );
    Ok(vec![
        "ProtectSystem=strict".to_owned(),
        "ProtectHome=read-only".to_owned(),
        format!("ReadWritePaths={home} /run/user/{} /tmp /var/tmp", user.uid),
    ])
}

pub fn manager_drop_in(user: &User) -> Result<String> {
    Ok(format!("[Service]\n{}\n", properties(user)?.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_unit_syntax() {
        for (home, accepted) in [
            ("/home/agent", true),
            ("/", false),
            ("/tmp/..", false),
            ("/home//agent", false),
            ("/home/a b", false),
            ("/home/%u", false),
            ("/home/a\nExecStart=evil", false),
        ] {
            let user = User {
                name: "agent".into(),
                uid: 1001,
                gid: 1001,
                home: home.into(),
            };
            assert_eq!(properties(&user).is_ok(), accepted, "{home:?}");
            if accepted {
                assert_eq!(
                    manager_drop_in(&user).unwrap(),
                    "[Service]\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=/home/agent /run/user/1001 /tmp /var/tmp\n"
                );
            }
        }
    }
}
