//! Lists files whose real contents a text search can't see.
//!
//! The check reads each file's first bytes rather than trusting its name, so a
//! program renamed to `logo.png` is still found.

use crate::archive::ArchiveFile;
use crate::report::{Kind, Report};

const PROGRAM_HEADERS: [&[u8]; 8] = [
    b"MZ",
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\0asm",
];
const ARCHIVE_HEADERS: [&[u8]; 7] = [
    b"PK\x03\x04",
    b"\x1f\x8b",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
    b"\xfd7zXZ\0",
    b"BZh",
    b"\x28\xb5\x2f\xfd",
];
const TAR_MAGIC_OFFSET: usize = 257;
const TAR_MAGIC: &[u8] = b"ustar";

/// Records a file if it is a compiled program or a compressed archive.
pub fn scan(file: &ArchiveFile, report: &mut Report) {
    if let Some(label) = label_for(&file.contents) {
        report.add(Kind::OpaqueFile, label, file.path.raw(), None);
    }
}

fn label_for(contents: &[u8]) -> Option<&'static str> {
    let starts_with_any = |headers: &[&[u8]]| headers.iter().any(|head| contents.starts_with(head));
    let is_tar = contents
        .get(TAR_MAGIC_OFFSET..)
        .is_some_and(|rest| rest.starts_with(TAR_MAGIC));

    if starts_with_any(&PROGRAM_HEADERS) {
        Some("Compiled programs")
    } else if starts_with_any(&ARCHIVE_HEADERS) || is_tar {
        Some("Compressed or packed archives")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_compiled_programs_whatever_they_are_named() {
        for contents in [
            &b"MZ\x90\0"[..],
            b"\x7fELF\x02\x01",
            b"\xcf\xfa\xed\xfe\x07",
            b"\xca\xfe\xba\xbe\0",
            b"\0asm\x01\0\0\0",
        ] {
            assert_eq!(
                label_for(contents),
                Some("Compiled programs"),
                "{contents:?}"
            );
        }
    }

    #[test]
    fn recognizes_archives() {
        for contents in [
            &b"PK\x03\x04\x14"[..],
            b"\x1f\x8b\x08\0",
            b"7z\xbc\xaf\x27\x1c\0",
            b"Rar!\x1a\x07\0",
            b"\xfd7zXZ\0\0",
            b"BZh91AY",
            b"\x28\xb5\x2f\xfd\0",
        ] {
            assert_eq!(
                label_for(contents),
                Some("Compressed or packed archives"),
                "{contents:?}"
            );
        }
    }

    #[test]
    fn recognizes_uncompressed_tar_archives() {
        let mut contents = vec![0u8; TAR_MAGIC_OFFSET];
        contents.extend_from_slice(b"ustar\0");

        assert_eq!(label_for(&contents), Some("Compressed or packed archives"));
    }

    #[test]
    fn leaves_ordinary_files_alone() {
        for contents in [
            &b""[..],
            b"M",
            b"fn main() {}",
            b"# README",
            b"\x89PNG\r\n\x1a\n",
            b"GIF89a",
        ] {
            assert_eq!(label_for(contents), None, "{contents:?}");
        }
    }

    #[test]
    fn lists_the_file_under_its_real_type() {
        let file = ArchiveFile {
            path: crate::text::Untrusted::from_bytes(b"assets/logo.png"),
            contents: b"MZ\x90\0".to_vec(),
        };
        let mut report = Report::new();

        scan(&file, &mut report);

        assert_eq!(
            report.listed(Kind::OpaqueFile),
            [("assets/logo.png".to_string(), 1)]
        );
    }
}
