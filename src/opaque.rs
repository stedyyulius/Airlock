//! Finds files whose real contents a text search can't see.
//!
//! The check reads each file's first bytes rather than trusting its name, so a
//! program renamed to `logo.png` is still found, and is reported as disguised.

use crate::git::RepoFile;
use crate::network::is_binary;
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

/// Extensions for files that should never really be programs or archives.
/// Anything else, such as `.dat` or no extension at all, is only listed as
/// unreadable, because plenty of real tools ship files like that.
const HARMLESS_LOOKING_EXTENSIONS: [&str; 44] = [
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "tiff", "txt", "md", "rst", "pdf",
    "csv", "json", "xml", "yaml", "yml", "toml", "ini", "cfg", "conf", "js", "mjs", "cjs", "ts",
    "jsx", "tsx", "css", "scss", "html", "htm", "py", "rb", "php", "sh", "go", "rs", "java", "ttf",
    "otf", "woff", "woff2", "mp4",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Packed {
    Program,
    Archive,
}

impl Packed {
    fn group(self) -> &'static str {
        match self {
            Self::Program => "Compiled programs",
            Self::Archive => "Compressed or packed archives",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::Program => "a program",
            Self::Archive => "an archive",
        }
    }
}

/// Records a file if it is a compiled program or a compressed archive.
pub fn scan(file: &RepoFile, report: &mut Report) {
    let Some(packed) = identify(&file.contents) else {
        return;
    };
    let path = file.path.raw();

    match harmless_looking_extension(path) {
        Some(extension) => {
            let detail = format!(
                "named like a .{extension} file, but it is {}",
                packed.noun()
            );
            report.add_detail(Kind::DisguisedFile, path, &detail);
        }
        None => report.add(Kind::OpaqueFile, packed.group(), path, None),
    }
}

fn identify(contents: &[u8]) -> Option<Packed> {
    let starts_with_any = |headers: &[&[u8]]| headers.iter().any(|head| contents.starts_with(head));
    let is_tar = contents
        .get(TAR_MAGIC_OFFSET..)
        .is_some_and(|rest| rest.starts_with(TAR_MAGIC));

    // Program headers are short enough to appear at the start of ordinary text,
    // such as "MZ" in a note, and real programs always contain zero bytes.
    if starts_with_any(&PROGRAM_HEADERS) && is_binary(contents) {
        Some(Packed::Program)
    } else if starts_with_any(&ARCHIVE_HEADERS) || is_tar {
        Some(Packed::Archive)
    } else {
        None
    }
}

fn harmless_looking_extension(path: &str) -> Option<String> {
    let name = path.rsplit('/').next()?;
    let (_, extension) = name.rsplit_once('.')?;
    let extension = extension.to_ascii_lowercase();

    HARMLESS_LOOKING_EXTENSIONS
        .contains(&extension.as_str())
        .then_some(extension)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::Untrusted;

    fn scan_file(path: &str, contents: &[u8]) -> Report {
        let file = RepoFile {
            path: Untrusted::from_bytes(path.as_bytes()),
            contents: contents.to_vec(),
        };
        let mut report = Report::new();
        scan(&file, &mut report);
        report
    }

    #[test]
    fn recognizes_compiled_programs() {
        for contents in [
            &b"MZ\x90\0"[..],
            b"\x7fELF\x02\x01\0",
            b"\xcf\xfa\xed\xfe\x07\0",
            b"\xca\xfe\xba\xbe\0",
            b"\0asm\x01\0\0\0",
        ] {
            assert_eq!(identify(contents), Some(Packed::Program), "{contents:?}");
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
            assert_eq!(identify(contents), Some(Packed::Archive), "{contents:?}");
        }
    }

    #[test]
    fn recognizes_uncompressed_tar_archives() {
        let mut contents = vec![0u8; TAR_MAGIC_OFFSET];
        contents.extend_from_slice(b"ustar\0");

        assert_eq!(identify(&contents), Some(Packed::Archive));
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
            // Text that happens to start the way a program does.
            b"MZ is the name of this module",
        ] {
            assert_eq!(identify(contents), None, "{contents:?}");
        }
    }

    #[test]
    fn a_program_named_like_an_image_is_disguised() {
        let report = scan_file("assets/LOGO.PNG", b"MZ\x90\0");

        assert_eq!(
            report
                .detail_of(Kind::DisguisedFile, "assets/LOGO.PNG")
                .as_deref(),
            Some("named like a .png file, but it is a program")
        );
        assert!(report.listed(Kind::OpaqueFile).is_empty());
    }

    #[test]
    fn an_archive_named_like_code_is_disguised() {
        let report = scan_file("src/util.js", b"PK\x03\x04\x14");

        assert_eq!(
            report
                .detail_of(Kind::DisguisedFile, "src/util.js")
                .as_deref(),
            Some("named like a .js file, but it is an archive")
        );
    }

    #[test]
    fn honestly_named_files_are_only_listed_as_unreadable() {
        for (path, contents) in [
            ("bin/tool.exe", &b"MZ\x90\0"[..]),
            ("bin/tool", b"\x7fELF\x02\x01\0"),
            ("lib/addon.node", b"\x7fELF\x02\x01\0"),
            ("data/blob.dat", b"MZ\x90\0"),
            ("tools/setup.zip", b"PK\x03\x04\x14"),
            ("dist/extension.js.gz", b"\x1f\x8b\x08\0"),
            ("libs/a.jar", b"PK\x03\x04\x14"),
        ] {
            let report = scan_file(path, contents);

            assert_eq!(report.listed(Kind::OpaqueFile).len(), 1, "path: {path}");
            assert!(
                report.listed(Kind::DisguisedFile).is_empty(),
                "path: {path}"
            );
        }
    }

    #[test]
    fn groups_unreadable_files_by_what_they_are() {
        let program = scan_file("bin/tool.exe", b"MZ\x90\0");
        let archive = scan_file("tools/setup.zip", b"PK\x03\x04\x14");

        assert_eq!(
            program
                .group_of(Kind::OpaqueFile, "bin/tool.exe")
                .as_deref(),
            Some("Compiled programs")
        );
        assert_eq!(
            archive
                .group_of(Kind::OpaqueFile, "tools/setup.zip")
                .as_deref(),
            Some("Compressed or packed archives")
        );
    }
}
