//! Checks where a repository's symbolic links point.
//!
//! A link can make a file inside the repository really be `~/.ssh/id_rsa`, so that
//! a tool uploading or printing the file gives away something else entirely.
//! Links that stay inside the repository are ordinary, and what they point at
//! gets read like any other file.

use crate::git::Link;
use crate::report::{Kind, Report};

/// Lists links that leave the repository.
pub fn report_links(links: &[Link], report: &mut Report) {
    for link in links {
        if leaves_repository(link.path.raw(), link.target.raw()) {
            report.add_detail(
                Kind::LinkOutside,
                link.path.raw(),
                &format!("points to {}", link.target.raw()),
            );
        }
    }
}

fn leaves_repository(path: &str, target: &str) -> bool {
    let target = target.replace('\\', "/");
    let is_absolute = target.starts_with('/')
        || target.starts_with('~')
        || target.as_bytes().get(1) == Some(&b':');
    if is_absolute {
        return true;
    }

    // How many folders down the link itself sits.
    let mut depth = path.matches('/').count() as i64;
    for piece in target.split('/') {
        match piece {
            "" | "." => {}
            ".." => depth -= 1,
            _ => depth += 1,
        }
        if depth < 0 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::Untrusted;

    fn link(path: &str, target: &str) -> Link {
        Link {
            path: Untrusted::from_bytes(path.as_bytes()),
            target: Untrusted::from_bytes(target.as_bytes()),
        }
    }

    #[test]
    fn links_leaving_the_repository_are_listed() {
        for (path, target) in [
            ("a", "/etc/passwd"),
            ("a", "~/.ssh/id_rsa"),
            ("a", "../outside"),
            ("a/b", "../../outside"),
            ("a", "c:\\windows\\system32"),
            ("a/b", "c/../../../outside"),
        ] {
            let mut report = Report::new();
            report_links(&[link(path, target)], &mut report);

            assert_eq!(
                report.listed(Kind::LinkOutside).len(),
                1,
                "{path} -> {target}"
            );
        }
    }

    #[test]
    fn links_staying_inside_are_fine() {
        for (path, target) in [
            ("a", "b"),
            ("a", "./b"),
            ("a/b", "../c"),
            ("a/b/c", "../../d/e"),
            ("a", "b/c/../d"),
        ] {
            let mut report = Report::new();
            report_links(&[link(path, target)], &mut report);

            assert!(
                report.listed(Kind::LinkOutside).is_empty(),
                "{path} -> {target}"
            );
        }
    }
}
