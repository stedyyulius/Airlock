//! Finds files whose real contents a text search can't see, and files that
//! aren't what their names say.
//!
//! The check reads each file's first bytes rather than trusting its name, so a
//! program renamed to `logo.png` is still found, and is reported as disguised.
//! So is a script renamed to `icons.woff2`, a trick used to get past people
//! skimming a repository, since nobody reads a font.

use crate::git::RepoFile;
use crate::network::{is_binary, is_test_path};
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

/// Media formats and how each one starts. If a file starts differently and reads
/// as text, it isn't what it says it is.
const MEDIA_HEADERS: [(&str, &[&[u8]]); 16] = [
    ("png", &[b"\x89PNG"]),
    ("jpg", &[b"\xff\xd8"]),
    ("jpeg", &[b"\xff\xd8"]),
    ("gif", &[b"GIF8"]),
    ("webp", &[b"RIFF"]),
    ("bmp", &[b"BM"]),
    ("ico", &[b"\0\0\x01\0", b"\0\0\x02\0"]),
    ("woff", &[b"wOFF"]),
    ("woff2", &[b"wOF2"]),
    ("ttf", &[b"\0\x01\0\0", b"true"]),
    ("otf", &[b"OTTO"]),
    ("mp3", &[b"ID3", b"\xff"]),
    ("wav", &[b"RIFF"]),
    ("pdf", &[b"%PDF"]),
    ("zip", &[b"PK"]),
    ("gz", &[b"\x1f\x8b"]),
];
const GIT_LFS_POINTER: &[u8] = b"version https://git-lfs.github.com/spec/v1";
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
const JPEG_END: &[u8] = b"\xff\xd9";
/// Honest tools can leave a little padding after an image's end.
const MIN_HIDDEN_BYTES: usize = 256;
/// Runs when double-clicked, and rarely a sign of anything good in a repository.
const CLICK_TO_RUN_EXTENSIONS: [&str; 15] = [
    "scr",
    "pif",
    "cpl",
    "lnk",
    "hta",
    "wsf",
    "wsh",
    "vbe",
    "jse",
    "vbs",
    "msi",
    "reg",
    "inf",
    "application",
    "appref-ms",
];
const RUNS_WHEN_CLICKED: &str = "File types that run when opened";
/// `invoice.pdf.exe` shows up as `invoice.pdf` when extensions are hidden.
const PROGRAM_EXTENSIONS: [&str; 13] = [
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "jse", "wsf", "hta", "lnk", "msi",
];
const DOCUMENT_EXTENSIONS: [&str; 15] = [
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "mp3",
    "mp4", "zip",
];
/// Folders holding installed packages, which package checks only see by name.
const INSTALLED_PACKAGE_FOLDERS: [&str; 3] = ["node_modules", "site-packages", ".venv"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Packed {
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
    let path = file.path.raw();
    scan_name(path, report);

    if file.contents.starts_with(GIT_LFS_POINTER) {
        let reason = "kept in Git LFS, so its real contents aren't in the repository";
        report.add_detail(Kind::NotRead, path, reason);
        return;
    }
    scan_media(file, report);

    let Some(packed) = identify(&file.contents) else {
        return;
    };

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

pub(crate) fn identify(contents: &[u8]) -> Option<Packed> {
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

/// Checks that a media file is what it says, with nothing tucked in after its end.
fn scan_media(file: &RepoFile, report: &mut Report) {
    let path = file.path.raw();
    let contents = file.contents.as_slice();
    let lower = path.to_ascii_lowercase();
    let Some((_, extension)) = lower.rsplit_once('.') else {
        return;
    };
    let Some((_, headers)) = MEDIA_HEADERS.iter().find(|(known, _)| *known == extension) else {
        return;
    };

    let is_real = headers.iter().any(|head| contents.starts_with(head));
    if !is_real && !contents.is_empty() && !is_binary(contents) {
        let detail = format!("named like a .{extension} file, but it is text");
        // Tests and examples can hold placeholder files that nothing runs.
        let is_example = lower.starts_with("examples/") || lower.contains("/examples/");
        if is_test_path(path) || is_example {
            report.add_detail(Kind::HiddenData, path, &detail);
        } else {
            report.add_detail(Kind::DisguisedFile, path, &detail);
            report.mark_disguised(path);
        }
        return;
    }

    let hidden = match extension {
        "png" => bytes_after_png(contents),
        "jpg" | "jpeg" => bytes_after_jpeg(contents),
        _ => 0,
    };
    if hidden >= MIN_HIDDEN_BYTES {
        let detail = format!("{hidden} extra bytes after the end of the image");
        report.add_detail(Kind::HiddenData, path, &detail);
    }
}

/// How much comes after a PNG's last chunk, found by walking the chunks.
fn bytes_after_png(contents: &[u8]) -> usize {
    if !contents.starts_with(PNG_SIGNATURE) {
        return 0;
    }
    let mut at = PNG_SIGNATURE.len();

    while let Some(header) = contents.get(at..at + 8) {
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let Some(end) = at.checked_add(12).and_then(|at| at.checked_add(length)) else {
            return 0;
        };
        if end > contents.len() {
            return 0;
        }
        if &header[4..8] == b"IEND" {
            return contents.len() - end;
        }
        at = end;
    }
    0
}

/// How much comes after a JPEG's last end marker.
fn bytes_after_jpeg(contents: &[u8]) -> usize {
    contents
        .windows(JPEG_END.len())
        .rposition(|window| window == JPEG_END)
        .map_or(0, |at| contents.len() - at - JPEG_END.len())
}

/// Checks a file's path for tricks in the name itself.
fn scan_name(path: &str, report: &mut Report) {
    let lower = path.to_ascii_lowercase();
    let segments: Vec<&str> = lower.split('/').collect();
    let name = segments.last().copied().unwrap_or("");

    let has_direction_override = path
        .chars()
        .any(|c| matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'));
    let has_invisible = path.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '\u{200b}'..='\u{200d}' | '\u{2060}' | '\u{feff}' | '\u{ad}'
            )
    });
    if has_direction_override {
        report.add_detail(
            Kind::DisguisedFile,
            path,
            "its name reverses text direction, so it may not end in what it appears to",
        );
    } else if has_invisible {
        report.add_detail(
            Kind::DisguisedFile,
            path,
            "its name contains invisible characters",
        );
    }

    // Windows drops these when unpacking, so `setup.py.` or `setup.py ` becomes
    // `setup.py` there, while a check for that exact name misses it.
    let has_vanishing_end = segments.iter().any(|segment| {
        segment.ends_with(' ') || (segment.ends_with('.') && *segment != "." && *segment != "..")
    });
    if has_vanishing_end {
        report.add_detail(
            Kind::DisguisedFile,
            path,
            "its name ends in a space or dot, which Windows removes",
        );
    }

    let mut pieces = name.rsplit('.');
    let last = pieces.next().unwrap_or("");
    let before_last = pieces.next().unwrap_or("");
    if PROGRAM_EXTENSIONS.contains(&last) && DOCUMENT_EXTENSIONS.contains(&before_last) {
        let detail = format!("looks like a .{before_last} file, but it is a .{last}");
        report.add_detail(Kind::DisguisedFile, path, &detail);
    }

    if CLICK_TO_RUN_EXTENSIONS.contains(&last) {
        report.add(Kind::OpaqueFile, RUNS_WHEN_CLICKED, path, None);
    }

    if !is_test_path(path) {
        let original: Vec<&str> = path.split('/').collect();
        let found = segments
            .iter()
            .position(|segment| INSTALLED_PACKAGE_FOLDERS.contains(segment));
        if let Some(at) = found {
            report.add(Kind::VendoredPackages, "", &original[..=at].join("/"), None);
        }
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
    fn a_script_named_like_a_font_or_image_is_disguised() {
        for path in [
            "public/fonts/icons.woff2",
            "assets/logo.png",
            "assets/photo.JPG",
            "static/a.ttf",
            "docs/a.pdf",
        ] {
            let report = scan_file(path, b"const a = require('child_process');\n");

            assert_eq!(report.listed(Kind::DisguisedFile).len(), 1, "{path}");
            assert!(report.is_disguised(path), "{path}");
        }
    }

    #[test]
    fn real_media_files_are_fine() {
        for (path, contents) in [
            ("a.png", &b"\x89PNG\r\n\x1a\n\0"[..]),
            ("a.jpg", b"\xff\xd8\xff\xe0\0"),
            ("a.gif", b"GIF89a\0"),
            ("a.woff2", b"wOF2\0"),
            ("a.woff", b"wOFF\0"),
            ("a.ttf", b"\0\x01\0\0\0"),
            ("a.pdf", b"%PDF-1.7\n"),
            // Empty files and types with no fixed start.
            ("empty.png", b""),
            ("a.svg", b"<svg></svg>"),
            ("a.css", b"a {}"),
        ] {
            let report = scan_file(path, contents);

            assert!(report.listed(Kind::DisguisedFile).is_empty(), "{path}");
        }
    }

    #[test]
    fn fake_media_in_tests_only_gets_a_warning() {
        let report = scan_file("tests/fixtures/fake.png", b"not an image\n");

        assert!(report.listed(Kind::DisguisedFile).is_empty());
        assert_eq!(report.listed(Kind::HiddenData).len(), 1);
    }

    #[test]
    fn files_kept_in_git_lfs_are_listed_as_not_read() {
        let pointer = b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 12\n";
        let report = scan_file("assets/model.png", pointer);

        assert_eq!(report.listed(Kind::NotRead).len(), 1);
        assert!(report.listed(Kind::DisguisedFile).is_empty());
    }

    fn png(extra: usize) -> Vec<u8> {
        let mut image = PNG_SIGNATURE.to_vec();
        image.extend_from_slice(&[0, 0, 0, 1]);
        image.extend_from_slice(b"IDAT\0");
        image.extend_from_slice(&[1, 2, 3, 4]);
        image.extend_from_slice(&[0, 0, 0, 0]);
        image.extend_from_slice(b"IEND");
        image.extend_from_slice(&[5, 6, 7, 8]);
        image.extend(std::iter::repeat_n(0, extra));
        image
    }

    #[test]
    fn finds_data_hidden_after_the_end_of_an_image() {
        let report = scan_file("a.png", &png(MIN_HIDDEN_BYTES));
        assert_eq!(report.listed(Kind::HiddenData).len(), 1);

        let mut jpeg = b"\xff\xd8\xff\xe0\xff\xd9".to_vec();
        jpeg.extend(std::iter::repeat_n(0, MIN_HIDDEN_BYTES));
        let report = scan_file("a.jpg", &jpeg);
        assert_eq!(report.listed(Kind::HiddenData).len(), 1);
    }

    #[test]
    fn images_with_nothing_after_their_end_are_fine() {
        assert!(
            scan_file("a.png", &png(0))
                .listed(Kind::HiddenData)
                .is_empty()
        );
        assert!(
            scan_file("a.jpg", b"\xff\xd8\xff\xe0\xff\xd9")
                .listed(Kind::HiddenData)
                .is_empty()
        );
    }

    #[test]
    fn broken_images_do_not_panic() {
        for contents in [
            &b"\x89PNG\r\n\x1a\n"[..],
            b"\x89PNG\r\n\x1a\n\xff\xff\xff\xffIDAT",
            b"\x89PNG\r\n\x1a\n\0\0",
            b"\xff\xd8",
        ] {
            scan_file("a.png", contents);
            scan_file("a.jpg", contents);
        }
    }

    #[test]
    fn finds_tricks_in_file_names() {
        for path in [
            "invoice.pdf.exe",
            "photo.jpg.scr",
            "docs/readme.txt.bat",
            "photo\u{202e}gpj.exe",
            "src/a\u{200b}.js",
            "setup.py ",
            "setup.py.",
            "node_modules /a.js",
        ] {
            let report = scan_file(path, b"x");

            assert_eq!(report.listed(Kind::DisguisedFile).len(), 1, "{path:?}");
        }
    }

    #[test]
    fn ordinary_names_are_fine() {
        for path in [
            "a.min.js",
            "icon.png.js",
            "../a/b.js",
            "a.d.ts",
            "v1.2.3.txt",
            "a..b.js",
        ] {
            let report = scan_file(path, b"x");

            assert!(report.listed(Kind::DisguisedFile).is_empty(), "{path}");
        }
    }

    #[test]
    fn lists_file_types_that_run_when_opened() {
        for path in ["a.lnk", "a.hta", "b/c.vbs", "a.scr", "a.reg"] {
            let report = scan_file(path, b"x");

            assert_eq!(
                report.group_of(Kind::OpaqueFile, path).as_deref(),
                Some(RUNS_WHEN_CLICKED),
                "{path}"
            );
        }
    }

    #[test]
    fn lists_installed_packages_committed_to_the_repository() {
        let first = scan_file("node_modules/a/index.js", b"x");
        assert_eq!(
            first.listed(Kind::VendoredPackages),
            [("node_modules".to_string(), 1)]
        );

        let nested = scan_file("web/node_modules/a/index.js", b"x");
        assert_eq!(
            nested.listed(Kind::VendoredPackages),
            [("web/node_modules".to_string(), 1)]
        );

        let test_fixture = scan_file("test/cases/node_modules/a/index.js", b"x");
        assert!(test_fixture.listed(Kind::VendoredPackages).is_empty());
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
