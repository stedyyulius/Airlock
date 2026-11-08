//! Saves a copy of the latest report, so it can still be read after it scrolls
//! away.
//!
//! There is only ever one file. Each scan replaces it, so reports can't pile up.
//! It holds only Airlock's own report, never files from the repository.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const REPORT_FILE: &str = "report.txt";
const TEMPORARY_FILE: &str = "report.txt.tmp";

/// Replaces the saved report with `text` and returns where it is.
pub fn save(text: &str) -> io::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|home| !home.is_empty())
        .ok_or_else(|| io::Error::other("no home folder found"))?;

    save_in(&PathBuf::from(home).join(".airlock"), text)
}

/// Writes a temporary file, then renames it over the old report. If saving fails
/// the previous report stays whole. A rename also replaces a planted symlink,
/// where opening the path for writing would overwrite whatever it points at.
fn save_in(dir: &Path, text: &str) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let temporary = dir.join(TEMPORARY_FILE);
    let report = dir.join(REPORT_FILE);

    // A crash during an earlier save can leave this behind.
    match fs::remove_file(&temporary) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }

    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .and_then(|mut file| file.write_all(text.as_bytes()));

    match written.and_then(|()| fs::rename(&temporary, &report)) {
        Ok(()) => Ok(report),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh folder for one test, removed when the test ends.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("airlock-test-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }

        fn entries(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn creates_the_folder_and_writes_the_report() {
        let test = TestDir::new("writes");

        let path = save_in(&test.0, "the report").unwrap();

        assert_eq!(path, test.0.join(REPORT_FILE));
        assert_eq!(fs::read_to_string(&path).unwrap(), "the report");
    }

    #[test]
    fn a_new_report_replaces_the_old_one_leaving_a_single_file() {
        let test = TestDir::new("replaces");

        save_in(&test.0, "a much longer first report").unwrap();
        let path = save_in(&test.0, "second").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
        assert_eq!(test.entries(), [REPORT_FILE]);
    }

    #[test]
    fn a_temporary_file_left_by_a_crash_does_not_block_saving() {
        let test = TestDir::new("stale");
        fs::create_dir_all(&test.0).unwrap();
        fs::write(test.0.join(TEMPORARY_FILE), "left behind").unwrap();

        let path = save_in(&test.0, "report").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "report");
        assert_eq!(test.entries(), [REPORT_FILE]);
    }

    #[test]
    fn a_failed_save_says_so_and_leaves_nothing_behind() {
        let test = TestDir::new("failed");
        fs::create_dir_all(test.0.join(REPORT_FILE)).unwrap();

        assert!(save_in(&test.0, "report").is_err());
        assert_eq!(test.entries(), [REPORT_FILE]);
    }

    #[test]
    fn reports_an_error_when_the_folder_cannot_be_created() {
        let test = TestDir::new("blocked");
        fs::create_dir_all(&test.0).unwrap();
        let blocker = test.0.join("file");
        fs::write(&blocker, "not a folder").unwrap();

        assert!(save_in(&blocker.join("airlock"), "report").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn does_not_write_through_planted_symlinks() {
        let test = TestDir::new("symlink");
        fs::create_dir_all(&test.0).unwrap();
        let victim = test.0.join("victim");
        fs::write(&victim, "original").unwrap();
        std::os::unix::fs::symlink(&victim, test.0.join(REPORT_FILE)).unwrap();
        std::os::unix::fs::symlink(&victim, test.0.join(TEMPORARY_FILE)).unwrap();

        let path = save_in(&test.0, "report").unwrap();

        assert_eq!(fs::read_to_string(&victim).unwrap(), "original");
        assert_eq!(fs::read_to_string(&path).unwrap(), "report");
        assert!(!fs::symlink_metadata(&path).unwrap().is_symlink());
    }
}
