//! Reads one commit of a repository through the git protocol, into memory.
//!
//! This is the same data `git clone` receives, which is the point. The archives
//! hosts offer for download can't be trusted here, because one line in
//! `.gitattributes` can leave a file out of them, and can leave itself out too.
//! A repository could show a scanner one set of files and `git clone` another.
//!
//! Nothing is written to disk and nothing is run. What the server sends is still
//! hostile input, so every size is capped, and a limit that would leave the result
//! incomplete is an error. Git names every object by the SHA-1 hash of its contents
//! and the walk starts from the commit that was asked for, so what gets read is
//! exactly that commit, whatever the server sends.

use crate::fetch::{self, FetchError};
use crate::source::Source;
use crate::text::Untrusted;
use flate2::{Decompress, FlushDecompress, Status};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read};
use std::rc::Rc;

const MIB: u64 = 1024 * 1024;
const ID_BYTES: usize = 20;
const HEX_ID_CHARS: usize = 40;
const SHA256_HEX_CHARS: usize = 64;
/// How many skipped files are listed. All of them are still counted.
const MAX_SKIPPED_KEPT: usize = 1000;
/// Git itself never builds chains anywhere near this long.
const MAX_DELTA_DEPTH: usize = 5000;
/// A pack's objects can refer forward, which takes more passes to untangle, but
/// git doesn't build packs that need many. This stops a pack built to be slow.
const MAX_RESOLVE_PASSES: usize = 16;
const MAX_FOLDER_DEPTH: usize = 1024;
const MAX_PATH_BYTES: usize = 16 * 1024;
const MAX_CACHED_BYTES: usize = 256 * 1024 * 1024;
const INFLATE_BUFFER_BYTES: usize = 64 * 1024;
const MAX_PKT_LINE_BYTES: usize = 65520;
const PKT_FLUSH: usize = 0;
const PKT_DELIMITER: usize = 1;
const PKT_RESPONSE_END: usize = 2;
const BAND_PACK: u8 = 1;
const BAND_PROGRESS: u8 = 2;
const BAND_ERROR: u8 = 3;

const MODE_TREE: u32 = 0o040000;
const MODE_LINK: u32 = 0o120000;
const MODE_SUBMODULE: u32 = 0o160000;

/// Upper bounds on what we are willing to process.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Size of the response, as received over the network.
    pub max_download_bytes: u64,
    /// Total size of the files handed over for checking.
    pub max_read_bytes: u64,
    /// Files larger than this are reported as skipped, not read into memory.
    pub max_file_bytes: u64,
    /// Files, folders and links. Repeating a folder is cheap for a repository to
    /// do, and repeating one inside another multiplies this very quickly.
    pub max_entries: u64,
    pub max_objects: u32,
    /// The largest object rebuilt from pieces. Larger ones can't be identified.
    pub max_rebuilt_bytes: u64,
    /// Everything decompressed or rebuilt along the way. Packs can be built to
    /// make this enormous, so without a cap a small pack could take hours.
    pub max_work_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_download_bytes: 512 * MIB,
            max_read_bytes: 1024 * MIB,
            max_file_bytes: 32 * MIB,
            max_entries: 200_000,
            max_objects: 2_000_000,
            max_rebuilt_bytes: 256 * MIB,
            max_work_bytes: 16 * 1024 * MIB,
        }
    }
}

/// One regular file from the repository.
#[derive(Debug)]
pub struct RepoFile {
    /// Path inside the repository.
    pub path: Untrusted,
    pub contents: Vec<u8>,
}

/// A file too large to read.
#[derive(Debug, PartialEq, Eq)]
pub struct Skipped {
    pub path: Untrusted,
    pub size: u64,
}

/// A symbolic link, and where it says it points.
#[derive(Debug, PartialEq, Eq)]
pub struct Link {
    pub path: Untrusted,
    pub target: Untrusted,
}

/// Another repository pinned at a commit, which `git clone --recursive` fetches.
#[derive(Debug, PartialEq, Eq)]
pub struct Submodule {
    pub path: Untrusted,
    pub commit: String,
}

/// What happened while reading a commit.
#[derive(Debug, Default)]
pub struct Summary {
    /// The first skipped files. `skipped_total` counts all of them.
    pub skipped: Vec<Skipped>,
    pub skipped_total: u64,
    pub links: Vec<Link>,
    pub submodules: Vec<Submodule>,
}

/// Why a commit could not be read completely.
#[derive(Debug)]
pub enum GitError {
    Fetch(FetchError),
    Connection(io::Error),
    Host(String),
    DownloadTooLarge { limit: u64 },
    ReadTooLarge { limit: u64 },
    WorkTooLarge,
    TooManyEntries { limit: u64 },
    TooManyObjects,
    ObjectTooLarge,
    Unsupported,
    Malformed(&'static str),
    Missing(&'static str),
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetch(error) => write!(f, "{error}"),
            Self::Connection(error) => write!(f, "the download failed: {error}"),
            Self::Host(message) => write!(f, "the host refused the request: {message}"),
            Self::DownloadTooLarge { limit } => {
                write!(
                    f,
                    "the repository is larger than the {} MiB limit",
                    limit / MIB
                )
            }
            Self::ReadTooLarge { limit } => {
                write!(
                    f,
                    "its files add up to more than the {} MiB limit",
                    limit / MIB
                )
            }
            Self::WorkTooLarge => write!(f, "refusing repository, it takes too much work to read"),
            Self::TooManyEntries { limit } => {
                write!(f, "the repository has more than {limit} files and folders")
            }
            Self::TooManyObjects => write!(f, "the repository has too many objects"),
            Self::ObjectTooLarge => write!(f, "refusing repository, an object is too large"),
            Self::Unsupported => write!(f, "this repository's object format isn't supported"),
            Self::Malformed(what) => write!(f, "the host sent unreadable data: {what}"),
            Self::Missing(what) => write!(f, "the host left out part of the commit: {what}"),
        }
    }
}

impl std::error::Error for GitError {}

/// Fetches one commit and calls `visit` for each regular file in it. With a folder
/// or file named, only that part of the commit is read.
pub fn read_commit(
    source: &Source,
    commit: &str,
    folder: Option<&str>,
    limits: &Limits,
    visit: impl FnMut(RepoFile),
) -> Result<Summary, GitError> {
    let response = fetch::post_stream(
        &format!("{}/git-upload-pack", source.git_url()),
        &[
            ("Content-Type", "application/x-git-upload-pack-request"),
            ("Accept", "application/x-git-upload-pack-result"),
            ("Git-Protocol", "version=2"),
        ],
        request_body(commit).as_bytes(),
    )
    .map_err(GitError::Fetch)?;

    let pack = read_response(response, limits)?;
    read_pack(&pack, commit, folder, limits, visit)
}

fn packet(text: &str) -> String {
    format!("{:04x}{text}", text.len() + 4)
}

/// Asks for one commit and no history. Without `thin-pack`, every object the pack
/// builds on is inside the pack.
fn request_body(commit: &str) -> String {
    let mut body = packet("command=fetch\n");
    body.push_str("0001");
    body.push_str(&packet("no-progress\n"));
    body.push_str(&packet("ofs-delta\n"));
    body.push_str(&packet("deepen 1\n"));
    body.push_str(&packet(&format!("want {commit}\n")));
    body.push_str(&packet("done\n"));
    body.push_str("0000");
    body
}

/// Reads the server's answer, a series of length-prefixed lines, and returns the
/// pack inside it. The pack's own lines each start with a byte saying what they are.
fn read_response<R: Read>(mut reader: R, limits: &Limits) -> Result<Vec<u8>, GitError> {
    let mut pack = Vec::new();
    let mut in_pack_section = false;
    let mut line = vec![0; MAX_PKT_LINE_BYTES];

    loop {
        let mut prefix = [0; 4];
        match read_all_or_end(&mut reader, &mut prefix).map_err(GitError::Connection)? {
            0 => break,
            4 => {}
            _ => return Err(GitError::Malformed("a cut off line")),
        }
        let length = std::str::from_utf8(&prefix)
            .ok()
            .and_then(|text| usize::from_str_radix(text, 16).ok())
            .ok_or(GitError::Malformed("a line with no length"))?;

        match length {
            PKT_FLUSH | PKT_RESPONSE_END => {
                if in_pack_section {
                    break;
                }
                continue;
            }
            PKT_DELIMITER => continue,
            3 => return Err(GitError::Malformed("a line with an impossible length")),
            _ => {}
        }
        let size = length - 4;
        if size > line.len() {
            return Err(GitError::Malformed("a line that is too long"));
        }
        reader
            .read_exact(&mut line[..size])
            .map_err(GitError::Connection)?;
        let data = &line[..size];

        if !in_pack_section {
            if data.starts_with(b"ERR ") {
                let message = Untrusted::from_bytes(data[4..].trim_ascii());
                return Err(GitError::Host(message.raw().to_string()));
            }
            in_pack_section = data.trim_ascii_end() == b"packfile";
            continue;
        }

        match data.first() {
            Some(&BAND_PACK) => {
                if (pack.len() + size) as u64 > limits.max_download_bytes {
                    return Err(GitError::DownloadTooLarge {
                        limit: limits.max_download_bytes,
                    });
                }
                pack.extend_from_slice(&data[1..]);
            }
            Some(&BAND_PROGRESS) => {}
            Some(&BAND_ERROR) => {
                let message = Untrusted::from_bytes(data[1..].trim_ascii());
                return Err(GitError::Host(message.raw().to_string()));
            }
            _ => return Err(GitError::Malformed("a line of an unknown kind")),
        }
    }
    if !in_pack_section {
        return Err(GitError::Missing("no objects were sent"));
    }
    Ok(pack)
}

/// Fills a buffer, returning how much was read. Less than the whole buffer means
/// the stream ended, which is only a problem part way through.
fn read_all_or_end<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Walks a pack from one commit down, calling `visit` for each file.
fn read_pack(
    bytes: &[u8],
    commit: &str,
    folder: Option<&str>,
    limits: &Limits,
    visit: impl FnMut(RepoFile),
) -> Result<Summary, GitError> {
    let wanted = parse_hex_id(commit).ok_or(GitError::Unsupported)?;
    let mut pack = Pack::parse(bytes, limits)?;
    pack.resolve_deltas()?;

    let tree = pack.tree_of_commit(&wanted)?;
    Walker {
        pack,
        limits,
        folder: folder.map(str::as_bytes),
        visit,
        entries: 0,
        read: 0,
        summary: Summary::default(),
    }
    .walk(tree)
}

fn parse_hex_id(text: &str) -> Option<[u8; ID_BYTES]> {
    if text.len() != HEX_ID_CHARS {
        return None;
    }
    let mut id = [0; ID_BYTES];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(id)
}

/// A commit's ID in text, which is 40 hex digits, or 64 in newer repositories.
pub fn is_commit_id(value: &str) -> bool {
    matches!(value.len(), HEX_ID_CHARS | SHA256_HEX_CHARS)
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex_id(id: &[u8]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectKind {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjectKind {
    fn name(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
        }
    }
}

/// What a pack entry is built on.
#[derive(Debug, Clone, Copy)]
enum Base {
    /// Nothing: the entry is a whole object.
    Whole(ObjectKind),
    /// An earlier entry in the pack.
    Entry(usize),
    /// An object named by its hash, which could be anywhere in the pack.
    Object([u8; ID_BYTES]),
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    /// Where its compressed data starts, and its size once decompressed.
    data: usize,
    stored_size: u64,
    base: Base,
    /// What it is once rebuilt, and how large. Unset until then.
    resolved: Option<(ObjectKind, u64)>,
}

/// A pack: every object for a commit, some stored as changes to other objects.
struct Pack<'a> {
    bytes: &'a [u8],
    entries: Vec<Entry>,
    by_id: HashMap<[u8; ID_BYTES], usize>,
    cache: HashMap<usize, Rc<Vec<u8>>>,
    cached_bytes: usize,
    work_left: u64,
    max_rebuilt_bytes: u64,
}

impl<'a> Pack<'a> {
    /// Reads through a whole pack once. Whole objects get identified straight
    /// away, by hashing them as they decompress.
    fn parse(bytes: &'a [u8], limits: &Limits) -> Result<Self, GitError> {
        const HEADER_BYTES: usize = 12;
        const MALFORMED_HEADER: GitError = GitError::Malformed("a broken pack header");

        if bytes.len() < HEADER_BYTES + ID_BYTES {
            return Err(MALFORMED_HEADER);
        }
        let (body, trailer) = bytes.split_at(bytes.len() - ID_BYTES);
        if !body.starts_with(b"PACK") {
            return Err(MALFORMED_HEADER);
        }
        if !matches!(body[4..8], [0, 0, 0, 2 | 3]) {
            return Err(GitError::Malformed("a pack version Airlock can't read"));
        }
        if Sha1::digest(body).as_slice() != trailer {
            return Err(GitError::Malformed("a pack that fails its checksum"));
        }
        let count = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
        if count > limits.max_objects {
            return Err(GitError::TooManyObjects);
        }

        let mut pack = Self {
            bytes: body,
            entries: Vec::new(),
            by_id: HashMap::new(),
            cache: HashMap::new(),
            cached_bytes: 0,
            work_left: limits.max_work_bytes,
            max_rebuilt_bytes: limits.max_rebuilt_bytes,
        };
        let mut starts = HashMap::new();
        let mut at = HEADER_BYTES;

        for index in 0..count as usize {
            starts.insert(at, index);
            let header = read_entry_header(body, at, &starts)?;

            let mut hash = Sha1::default();
            if let Base::Whole(kind) = header.base {
                hash.update(object_header(kind, header.size).as_bytes());
            }
            let used = inflate(
                &body[header.data..],
                header.size,
                &mut pack.work_left,
                |piece| {
                    if matches!(header.base, Base::Whole(_)) {
                        hash.update(piece);
                    }
                },
            )?;

            let resolved = match header.base {
                Base::Whole(kind) => {
                    pack.by_id.insert(hash.finish(), index);
                    Some((kind, header.size))
                }
                Base::Entry(_) | Base::Object(_) => None,
            };
            pack.entries.push(Entry {
                data: header.data,
                stored_size: header.size,
                base: header.base,
                resolved,
            });
            at = header.data + used;
        }
        if at != body.len() {
            return Err(GitError::Malformed("extra data after the last object"));
        }
        Ok(pack)
    }

    fn spend(&mut self, bytes: u64) -> Result<(), GitError> {
        self.work_left = self
            .work_left
            .checked_sub(bytes)
            .ok_or(GitError::WorkTooLarge)?;
        Ok(())
    }

    /// Rebuilds every stored change, so that each object has its name. An entry
    /// that can't be rebuilt only matters if the commit turns out to need it.
    fn resolve_deltas(&mut self) -> Result<(), GitError> {
        let mut pending: Vec<usize> = (0..self.entries.len())
            .filter(|index| self.entries[*index].resolved.is_none())
            .collect();

        for _ in 0..MAX_RESOLVE_PASSES {
            let before = pending.len();
            let mut left = Vec::new();

            for index in pending {
                match self.resolve_one(index) {
                    Ok(()) => {}
                    Err(GitError::Missing(_)) => left.push(index),
                    Err(error) => return Err(error),
                }
            }
            pending = left;
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        Ok(())
    }

    fn resolve_one(&mut self, index: usize) -> Result<(), GitError> {
        let kind = self.kind_of(index)?;
        let content = self.content(index)?;

        let mut hash = Sha1::default();
        hash.update(object_header(kind, content.len() as u64).as_bytes());
        hash.update(&content);

        self.entries[index].resolved = Some((kind, content.len() as u64));
        self.by_id.insert(hash.finish(), index);
        Ok(())
    }

    /// An object's kind comes from whatever whole object it was built from.
    fn kind_of(&self, index: usize) -> Result<ObjectKind, GitError> {
        let mut current = index;
        for _ in 0..=MAX_DELTA_DEPTH {
            current = match self.entries[current].base {
                Base::Whole(kind) => return Ok(kind),
                Base::Entry(base) => base,
                Base::Object(id) => *self
                    .by_id
                    .get(&id)
                    .ok_or(GitError::Missing("an object another is built from"))?,
            };
        }
        Err(GitError::Malformed(
            "objects built on each other too deeply",
        ))
    }

    /// An object's full contents. Stored changes get applied in order, starting
    /// from the nearest thing already known.
    fn content(&mut self, index: usize) -> Result<Rc<Vec<u8>>, GitError> {
        let mut chain = Vec::new();
        let mut current = index;

        let mut content = loop {
            if let Some(found) = self.cache.get(&current) {
                break Rc::clone(found);
            }
            match self.entries[current].base {
                Base::Whole(_) => {
                    let whole = self.inflate_entry(current)?;
                    break Rc::new(whole);
                }
                Base::Entry(base) => {
                    chain.push(current);
                    current = base;
                }
                Base::Object(id) => {
                    chain.push(current);
                    current = *self
                        .by_id
                        .get(&id)
                        .ok_or(GitError::Missing("an object another is built from"))?;
                }
            }
            if chain.len() > MAX_DELTA_DEPTH {
                return Err(GitError::Malformed(
                    "objects built on each other too deeply",
                ));
            }
        };

        while let Some(next) = chain.pop() {
            self.remember(current, &content);
            let delta = self.inflate_entry(next)?;
            let rebuilt = apply_delta(&content, &delta, self.max_rebuilt_bytes)?;
            self.spend(rebuilt.len() as u64)?;
            content = Rc::new(rebuilt);
            current = next;
        }
        self.remember(current, &content);
        Ok(content)
    }

    fn remember(&mut self, index: usize, content: &Rc<Vec<u8>>) {
        if content.len() > MAX_CACHED_BYTES / 4 || self.cache.contains_key(&index) {
            return;
        }
        if self.cached_bytes + content.len() > MAX_CACHED_BYTES {
            self.cache.clear();
            self.cached_bytes = 0;
        }
        self.cached_bytes += content.len();
        self.cache.insert(index, Rc::clone(content));
    }

    /// Decompresses what's stored for an entry, which for a change is the change.
    fn inflate_entry(&mut self, index: usize) -> Result<Vec<u8>, GitError> {
        let Entry {
            data, stored_size, ..
        } = self.entries[index];
        let mut output = Vec::with_capacity(stored_size.min(MIB * 8) as usize);
        inflate(
            &self.bytes[data..],
            stored_size,
            &mut self.work_left,
            |piece| {
                output.extend_from_slice(piece);
            },
        )?;
        Ok(output)
    }

    fn entry_with_id(&self, id: &[u8; ID_BYTES], what: &'static str) -> Result<usize, GitError> {
        self.by_id.get(id).copied().ok_or(GitError::Missing(what))
    }

    /// Finds the top-level folder of a commit.
    fn tree_of_commit(&mut self, commit: &[u8; ID_BYTES]) -> Result<[u8; ID_BYTES], GitError> {
        let index = self.entry_with_id(commit, "the commit itself")?;
        if !matches!(self.entries[index].resolved, Some((ObjectKind::Commit, _))) {
            return Err(GitError::Malformed("what was asked for isn't a commit"));
        }
        let content = self.content(index)?;
        let tree = content
            .strip_prefix(b"tree ")
            .and_then(|rest| rest.get(..HEX_ID_CHARS))
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(parse_hex_id);
        tree.ok_or(GitError::Malformed("a commit with no folder"))
    }
}

struct EntryHeader {
    base: Base,
    size: u64,
    data: usize,
}

/// Reads an entry's type, size and what it's built on.
fn read_entry_header(
    pack: &[u8],
    start: usize,
    starts: &HashMap<usize, usize>,
) -> Result<EntryHeader, GitError> {
    const BROKEN: GitError = GitError::Malformed("a broken object header");

    let mut at = start;
    let mut byte = *pack.get(at).ok_or(BROKEN)?;
    at += 1;
    let kind = (byte >> 4) & 0x07;
    let mut size = u64::from(byte & 0x0f);
    let mut shift = 4;
    while byte & 0x80 != 0 {
        byte = *pack.get(at).ok_or(BROKEN)?;
        at += 1;
        if shift > 57 {
            return Err(BROKEN);
        }
        size |= u64::from(byte & 0x7f) << shift;
        shift += 7;
    }

    let base = match kind {
        1 => Base::Whole(ObjectKind::Commit),
        2 => Base::Whole(ObjectKind::Tree),
        3 => Base::Whole(ObjectKind::Blob),
        4 => Base::Whole(ObjectKind::Tag),
        6 => {
            let mut byte = *pack.get(at).ok_or(BROKEN)?;
            at += 1;
            let mut distance = u64::from(byte & 0x7f);
            while byte & 0x80 != 0 {
                byte = *pack.get(at).ok_or(BROKEN)?;
                at += 1;
                distance = distance
                    .checked_add(1)
                    .and_then(|value| value.checked_mul(128))
                    .and_then(|value| value.checked_add(u64::from(byte & 0x7f)))
                    .ok_or(BROKEN)?;
            }
            let base_start = u64::try_from(start)
                .ok()
                .and_then(|start| start.checked_sub(distance))
                .ok_or(BROKEN)? as usize;
            // Only entries before this one can be the base.
            if distance == 0 {
                return Err(BROKEN);
            }
            Base::Entry(*starts.get(&base_start).ok_or(BROKEN)?)
        }
        7 => {
            let id = pack.get(at..at + ID_BYTES).ok_or(BROKEN)?;
            at += ID_BYTES;
            let mut base = [0; ID_BYTES];
            base.copy_from_slice(id);
            Base::Object(base)
        }
        _ => return Err(BROKEN),
    };

    Ok(EntryHeader {
        base,
        size,
        data: at,
    })
}

fn object_header(kind: ObjectKind, size: u64) -> String {
    format!("{} {size}\0", kind.name())
}

/// Decompresses one stream, returning how many compressed bytes it used. Packs
/// give no other way to find where the next entry starts. The size is declared by
/// the pack, so going past it stops here rather than filling memory.
fn inflate(
    input: &[u8],
    declared: u64,
    work_left: &mut u64,
    mut sink: impl FnMut(&[u8]),
) -> Result<usize, GitError> {
    const BROKEN: GitError = GitError::Malformed("compressed data that can't be read");

    let mut decoder = Decompress::new(true);
    let mut buffer = vec![0; INFLATE_BUFFER_BYTES];

    loop {
        let read_before = decoder.total_in();
        let written_before = decoder.total_out();
        let status = decoder
            .decompress(
                &input[decoder.total_in() as usize..],
                &mut buffer,
                FlushDecompress::None,
            )
            .map_err(|_| BROKEN)?;
        let written = (decoder.total_out() - written_before) as usize;

        if decoder.total_out() > declared {
            return Err(GitError::Malformed("an object larger than it says"));
        }
        *work_left = work_left
            .checked_sub(written as u64)
            .ok_or(GitError::WorkTooLarge)?;
        sink(&buffer[..written]);

        match status {
            Status::StreamEnd => {
                if decoder.total_out() != declared {
                    return Err(GitError::Malformed("an object smaller than it says"));
                }
                return Ok(decoder.total_in() as usize);
            }
            Status::Ok | Status::BufError => {
                if written == 0 && decoder.total_in() == read_before {
                    return Err(BROKEN);
                }
            }
        }
    }
}

/// Reads a size at the start of a stored change, returning what's left after it.
fn read_delta_size(delta: &[u8]) -> Option<(u64, &[u8])> {
    let mut size = 0_u64;
    let mut shift = 0;
    for (index, byte) in delta.iter().enumerate() {
        if shift > 57 {
            return None;
        }
        size |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((size, &delta[index + 1..]));
        }
    }
    None
}

/// Rebuilds an object from the one it's based on and a list of changes, which are
/// either copies from the base or new bytes.
fn apply_delta(base: &[u8], delta: &[u8], max_bytes: u64) -> Result<Vec<u8>, GitError> {
    const BROKEN: GitError = GitError::Malformed("a stored change that can't be applied");

    let (base_size, rest) = read_delta_size(delta).ok_or(BROKEN)?;
    if base_size != base.len() as u64 {
        return Err(BROKEN);
    }
    let (result_size, mut rest) = read_delta_size(rest).ok_or(BROKEN)?;
    if result_size > max_bytes {
        return Err(GitError::ObjectTooLarge);
    }
    let result_size = result_size as usize;
    let mut output = Vec::with_capacity(result_size);

    while let Some((&op, tail)) = rest.split_first() {
        rest = tail;
        if op & 0x80 != 0 {
            let mut offset = 0_usize;
            let mut length = 0_usize;
            for bit in 0..4 {
                if op & (1 << bit) != 0 {
                    let (&byte, tail) = rest.split_first().ok_or(BROKEN)?;
                    rest = tail;
                    offset |= usize::from(byte) << (bit * 8);
                }
            }
            for bit in 0..3 {
                if op & (0x10 << bit) != 0 {
                    let (&byte, tail) = rest.split_first().ok_or(BROKEN)?;
                    rest = tail;
                    length |= usize::from(byte) << (bit * 8);
                }
            }
            if length == 0 {
                length = 0x10000;
            }
            let end = offset.checked_add(length).ok_or(BROKEN)?;
            let copied = base.get(offset..end).ok_or(BROKEN)?;
            if output.len() + copied.len() > result_size {
                return Err(BROKEN);
            }
            output.extend_from_slice(copied);
        } else if op != 0 {
            let length = usize::from(op);
            let added = rest.get(..length).ok_or(BROKEN)?;
            rest = &rest[length..];
            if output.len() + added.len() > result_size {
                return Err(BROKEN);
            }
            output.extend_from_slice(added);
        } else {
            return Err(BROKEN);
        }
    }
    if output.len() != result_size {
        return Err(BROKEN);
    }
    Ok(output)
}

struct TreeEntry<'a> {
    mode: u32,
    name: &'a [u8],
    id: [u8; ID_BYTES],
}

/// Splits a folder object into its entries, each `mode name\0id`.
fn parse_tree(mut tree: &[u8]) -> Result<Vec<TreeEntry<'_>>, GitError> {
    const BROKEN: GitError = GitError::Malformed("a folder that can't be read");
    let mut entries = Vec::new();

    while !tree.is_empty() {
        let space = tree.iter().position(|byte| *byte == b' ').ok_or(BROKEN)?;
        let mode = std::str::from_utf8(&tree[..space]).map_err(|_| BROKEN)?;
        let mode = u32::from_str_radix(mode, 8).map_err(|_| BROKEN)?;
        let rest = &tree[space + 1..];

        let end = rest.iter().position(|byte| *byte == 0).ok_or(BROKEN)?;
        let name = &rest[..end];
        let rest = &rest[end + 1..];
        let id = rest.get(..ID_BYTES).ok_or(BROKEN)?;

        let mut entry_id = [0; ID_BYTES];
        entry_id.copy_from_slice(id);
        entries.push(TreeEntry {
            mode,
            name,
            id: entry_id,
        });
        tree = &rest[ID_BYTES..];
    }
    Ok(entries)
}

/// Goes through a commit's folders, handing over its files.
struct Walker<'a, F> {
    pack: Pack<'a>,
    limits: &'a Limits,
    folder: Option<&'a [u8]>,
    visit: F,
    entries: u64,
    read: u64,
    summary: Summary,
}

impl<F: FnMut(RepoFile)> Walker<'_, F> {
    fn walk(mut self, root: [u8; ID_BYTES]) -> Result<Summary, GitError> {
        // A list rather than recursion, because a repository chooses how deep this
        // goes, and running out of stack would end the program with no explanation.
        let mut folders = vec![(Vec::new(), root, 0_usize)];

        while let Some((path, id, depth)) = folders.pop() {
            if depth > MAX_FOLDER_DEPTH {
                return Err(GitError::Malformed("folders nested too deeply"));
            }
            let index = self.pack.entry_with_id(&id, "a folder")?;
            if !matches!(
                self.pack.entries[index].resolved,
                Some((ObjectKind::Tree, _))
            ) {
                return Err(GitError::Malformed(
                    "something listed as a folder isn't one",
                ));
            }
            let content = self.pack.content(index)?;

            for entry in parse_tree(&content)? {
                self.entries += 1;
                if self.entries > self.limits.max_entries {
                    return Err(GitError::TooManyEntries {
                        limit: self.limits.max_entries,
                    });
                }

                let mut full_path = path.clone();
                if !full_path.is_empty() {
                    full_path.push(b'/');
                }
                full_path.extend_from_slice(entry.name);
                if full_path.len() > MAX_PATH_BYTES {
                    return Err(GitError::Malformed("a path that is too long"));
                }

                if !self.is_wanted(&full_path, entry.mode == MODE_TREE) {
                    continue;
                }
                match entry.mode {
                    MODE_TREE => folders.push((full_path, entry.id, depth + 1)),
                    MODE_SUBMODULE => self.summary.submodules.push(Submodule {
                        path: Untrusted::from_bytes(&full_path),
                        commit: hex_id(&entry.id),
                    }),
                    MODE_LINK => self.read_link(&full_path, &entry.id)?,
                    _ => self.read_file(full_path, &entry.id)?,
                }
            }
        }
        Ok(self.summary)
    }

    /// Whether a path is inside the part that was asked for, or leads to it.
    fn is_wanted(&self, path: &[u8], is_folder: bool) -> bool {
        let Some(folder) = self.folder else {
            return true;
        };
        let inside = path == folder
            || path
                .strip_prefix(folder)
                .is_some_and(|rest| rest.starts_with(b"/"));
        let leads_there = is_folder
            && folder
                .strip_prefix(path)
                .is_some_and(|rest| rest.starts_with(b"/"));
        inside || leads_there
    }

    fn read_link(&mut self, path: &[u8], id: &[u8; ID_BYTES]) -> Result<(), GitError> {
        let index = self.pack.entry_with_id(id, "a link")?;
        let size = self.pack.entries[index]
            .resolved
            .map_or(0, |(_, size)| size);
        if size > self.limits.max_file_bytes {
            return Err(GitError::Malformed("a link that is far too long"));
        }
        let target = self.pack.content(index)?;
        self.summary.links.push(Link {
            path: Untrusted::from_bytes(path),
            target: Untrusted::from_bytes(&target),
        });
        Ok(())
    }

    fn read_file(&mut self, path: Vec<u8>, id: &[u8; ID_BYTES]) -> Result<(), GitError> {
        let index = self.pack.entry_with_id(id, "a file")?;
        let Some((kind, size)) = self.pack.entries[index].resolved else {
            return Err(GitError::Missing("a file"));
        };
        if kind != ObjectKind::Blob {
            return Err(GitError::Malformed("something listed as a file isn't one"));
        }

        let path = Untrusted::from_bytes(&path);
        if size > self.limits.max_file_bytes {
            self.summary.skipped_total += 1;
            if self.summary.skipped.len() < MAX_SKIPPED_KEPT {
                self.summary.skipped.push(Skipped { path, size });
            }
            return Ok(());
        }

        self.read += size;
        if self.read > self.limits.max_read_bytes {
            return Err(GitError::ReadTooLarge {
                limit: self.limits.max_read_bytes,
            });
        }
        let content = self.pack.content(index)?;
        let contents = Rc::try_unwrap(content).unwrap_or_else(|shared| (*shared).clone());
        (self.visit)(RepoFile { path, contents });
        Ok(())
    }
}

/// The SHA-1 hash, which git uses to name objects. A small implementation, because
/// it's the only hash needed, and this is a tool that should have few dependencies.
struct Sha1 {
    state: [u32; 5],
    pending: [u8; 64],
    pending_len: usize,
    total_len: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
            pending: [0; 64],
            pending_len: 0,
            total_len: 0,
        }
    }
}

impl Sha1 {
    fn digest(data: &[u8]) -> [u8; ID_BYTES] {
        let mut hash = Self::default();
        hash.update(data);
        hash.finish()
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.pending_len > 0 {
            let wanted = (64 - self.pending_len).min(data.len());
            self.pending[self.pending_len..self.pending_len + wanted]
                .copy_from_slice(&data[..wanted]);
            self.pending_len += wanted;
            data = &data[wanted..];
            if self.pending_len < 64 {
                return;
            }
            let block = self.pending;
            self.process(&block);
            self.pending_len = 0;
        }

        let mut blocks = data.chunks_exact(64);
        for block in blocks.by_ref() {
            self.process(block);
        }
        let rest = blocks.remainder();
        self.pending[..rest.len()].copy_from_slice(rest);
        self.pending_len = rest.len();
    }

    fn finish(mut self) -> [u8; ID_BYTES] {
        let bits = self.total_len.wrapping_mul(8);
        let padding_len = if self.pending_len < 56 {
            56 - self.pending_len
        } else {
            120 - self.pending_len
        };
        let mut padding = [0; 72];
        padding[0] = 0x80;
        padding[padding_len..padding_len + 8].copy_from_slice(&bits.to_be_bytes());
        let total = self.total_len;
        self.update(&padding[..padding_len + 8]);
        self.total_len = total;

        let mut digest = [0; ID_BYTES];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn process(&mut self, block: &[u8]) {
        let mut words = [0_u32; 80];
        for (word, bytes) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (index, word) in words.iter().enumerate() {
            let (mix, constant) = match index {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6_u32),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(mix)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (slot, value) in self.state.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn object_id(kind: ObjectKind, data: &[u8]) -> [u8; ID_BYTES] {
        let mut hash = Sha1::default();
        hash.update(object_header(kind, data.len() as u64).as_bytes());
        hash.update(data);
        hash.finish()
    }

    /// Builds packs by hand, so tests can make them as strange as they like.
    #[derive(Default)]
    struct PackBuilder {
        body: Vec<u8>,
        count: u32,
    }

    impl PackBuilder {
        fn entry_header(&mut self, kind: u8, size: usize) {
            let mut size = size as u64;
            let mut byte = (kind << 4) | (size & 0x0f) as u8;
            size >>= 4;
            while size > 0 {
                self.body.push(byte | 0x80);
                byte = (size & 0x7f) as u8;
                size >>= 7;
            }
            self.body.push(byte);
        }

        /// Adds a whole object and returns its name.
        fn whole(&mut self, kind: ObjectKind, data: &[u8]) -> [u8; ID_BYTES] {
            let number = match kind {
                ObjectKind::Commit => 1,
                ObjectKind::Tree => 2,
                ObjectKind::Blob => 3,
                ObjectKind::Tag => 4,
            };
            self.entry_header(number, data.len());
            self.body.extend_from_slice(&deflate(data));
            self.count += 1;
            object_id(kind, data)
        }

        fn blob(&mut self, data: &[u8]) -> [u8; ID_BYTES] {
            self.whole(ObjectKind::Blob, data)
        }

        fn tree(&mut self, entries: &[(&str, &[u8], [u8; ID_BYTES])]) -> [u8; ID_BYTES] {
            let data = tree_bytes(entries);
            self.whole(ObjectKind::Tree, &data)
        }

        fn commit(&mut self, tree: [u8; ID_BYTES]) -> [u8; ID_BYTES] {
            let text = format!("tree {}\nauthor a\n\nmessage\n", hex_id(&tree));
            self.whole(ObjectKind::Commit, text.as_bytes())
        }

        /// Adds a change based on an object named by its hash.
        fn ref_delta(&mut self, base: [u8; ID_BYTES], delta: &[u8]) {
            self.entry_header(7, delta.len());
            self.body.extend_from_slice(&base);
            self.body.extend_from_slice(&deflate(delta));
            self.count += 1;
        }

        /// Adds a change based on an earlier entry, `distance` bytes back.
        fn ofs_delta(&mut self, distance: u64, delta: &[u8]) {
            self.entry_header(6, delta.len());
            let mut bytes = vec![(distance & 0x7f) as u8];
            let mut left = distance >> 7;
            while left > 0 {
                left -= 1;
                bytes.push(0x80 | (left & 0x7f) as u8);
                left >>= 7;
            }
            bytes.reverse();
            self.body.extend_from_slice(&bytes);
            self.body.extend_from_slice(&deflate(delta));
            self.count += 1;
        }

        fn finish(self) -> Vec<u8> {
            let mut pack = b"PACK\0\0\0\x02".to_vec();
            pack.extend_from_slice(&self.count.to_be_bytes());
            pack.extend_from_slice(&self.body);
            let digest = Sha1::digest(&pack);
            pack.extend_from_slice(&digest);
            pack
        }
    }

    fn tree_bytes(entries: &[(&str, &[u8], [u8; ID_BYTES])]) -> Vec<u8> {
        let mut data = Vec::new();
        for (mode, name, id) in entries {
            data.extend_from_slice(mode.as_bytes());
            data.push(b' ');
            data.extend_from_slice(name);
            data.push(0);
            data.extend_from_slice(id);
        }
        data
    }

    /// A change turning `base` into `base` followed by `added`.
    fn delta_appending(base: &[u8], added: &[u8]) -> Vec<u8> {
        let mut delta = Vec::new();
        write_delta_size(&mut delta, base.len() as u64);
        write_delta_size(&mut delta, (base.len() + added.len()) as u64);
        // Copy everything: offset 0, with the length in one or two bytes.
        delta.push(0x80 | 0x10 | 0x20);
        delta.push((base.len() & 0xff) as u8);
        delta.push((base.len() >> 8) as u8);
        delta.push(added.len() as u8);
        delta.extend_from_slice(added);
        delta
    }

    fn write_delta_size(out: &mut Vec<u8>, mut size: u64) {
        while size >= 0x80 {
            out.push((size & 0x7f) as u8 | 0x80);
            size >>= 7;
        }
        out.push(size as u8);
    }

    struct Read {
        files: Vec<(String, Vec<u8>)>,
        summary: Summary,
    }

    fn read_with(pack: &[u8], commit: [u8; ID_BYTES], limits: &Limits) -> Result<Read, GitError> {
        read_folder(pack, commit, None, limits)
    }

    fn read_folder(
        pack: &[u8],
        commit: [u8; ID_BYTES],
        folder: Option<&str>,
        limits: &Limits,
    ) -> Result<Read, GitError> {
        let mut files = Vec::new();
        let summary = read_pack(pack, &hex_id(&commit), folder, limits, |file| {
            files.push((file.path.raw().to_string(), file.contents));
        })?;
        files.sort();
        Ok(Read { files, summary })
    }

    fn read_ok(pack: &[u8], commit: [u8; ID_BYTES]) -> Read {
        read_with(pack, commit, &Limits::default()).unwrap()
    }

    fn sample_pack() -> (Vec<u8>, [u8; ID_BYTES]) {
        let mut builder = PackBuilder::default();
        let readme = builder.blob(b"hello\n");
        let script = builder.blob(b"#!/bin/sh\n");
        let inner = builder.tree(&[("100755", b"run.sh", script)]);
        let root = builder.tree(&[("100644", b"README.md", readme), ("40000", b"bin", inner)]);
        let commit = builder.commit(root);
        (builder.finish(), commit)
    }

    #[test]
    fn recognizes_commit_ids() {
        assert!(is_commit_id(&"a".repeat(40)));
        assert!(is_commit_id(&"0".repeat(64)));
        for value in [
            "main",
            "",
            "abc123",
            &"a".repeat(39),
            &"g".repeat(40),
            &"A".repeat(40),
        ] {
            assert!(!is_commit_id(value), "{value}");
        }
    }

    #[test]
    fn hashes_match_the_published_test_values() {
        for (input, expected) in [
            (&b""[..], "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            ),
        ] {
            assert_eq!(hex_id(&Sha1::digest(input)), expected);
        }
        assert_eq!(
            hex_id(&Sha1::digest(&vec![b'a'; 1_000_000])),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn hashing_in_pieces_gives_the_same_answer() {
        let data = vec![7_u8; 1000];
        for piece in [1, 3, 63, 64, 65, 127, 999] {
            let mut hash = Sha1::default();
            for chunk in data.chunks(piece) {
                hash.update(chunk);
            }
            assert_eq!(hash.finish(), Sha1::digest(&data), "{piece}");
        }
    }

    #[test]
    fn names_objects_the_way_git_does() {
        // `git hash-object` gives this for the same contents.
        assert_eq!(
            hex_id(&object_id(ObjectKind::Blob, b"hello\n")),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
    }

    #[test]
    fn reads_every_file_in_a_commit() {
        let (pack, commit) = sample_pack();

        let read = read_ok(&pack, commit);

        assert_eq!(
            read.files,
            [
                ("README.md".to_string(), b"hello\n".to_vec()),
                ("bin/run.sh".to_string(), b"#!/bin/sh\n".to_vec()),
            ]
        );
    }

    #[test]
    fn can_read_just_one_folder_or_file() {
        let (pack, commit) = sample_pack();
        let limits = Limits::default();

        let names = |folder| -> Vec<String> {
            read_folder(&pack, commit, Some(folder), &limits)
                .unwrap()
                .files
                .into_iter()
                .map(|(name, _)| name)
                .collect()
        };

        assert_eq!(names("bin"), ["bin/run.sh"]);
        assert_eq!(names("bin/run.sh"), ["bin/run.sh"]);
        assert_eq!(names("README.md"), ["README.md"]);
        assert!(names("bi").is_empty());
        assert!(names("missing").is_empty());
    }

    #[test]
    fn reads_objects_stored_as_changes_to_other_objects() {
        let mut builder = PackBuilder::default();
        let base = b"the original text\n";
        let start = builder.body.len() as u64;
        let base_id = builder.blob(base);

        let first = delta_appending(base, b"added by offset\n");
        let distance = builder.body.len() as u64 - start;
        let first_text = [&base[..], b"added by offset\n"].concat();
        builder.ofs_delta(distance, &first);

        let second = delta_appending(base, b"added by name\n");
        let second_text = [&base[..], b"added by name\n"].concat();
        builder.ref_delta(base_id, &second);

        let root = builder.tree(&[
            ("100644", b"a", base_id),
            ("100644", b"b", object_id(ObjectKind::Blob, &first_text)),
            ("100644", b"c", object_id(ObjectKind::Blob, &second_text)),
        ]);
        let commit = builder.commit(root);

        let read = read_ok(&builder.finish(), commit);

        assert_eq!(read.files[1].1, first_text);
        assert_eq!(read.files[2].1, second_text);
    }

    #[test]
    fn reads_changes_built_on_changes_in_any_order() {
        let base = b"base text\n".to_vec();
        let middle = [&base[..], b"middle\n"].concat();
        let last = [&middle[..], b"last\n"].concat();
        let middle_id = object_id(ObjectKind::Blob, &middle);

        let mut builder = PackBuilder::default();
        // This one comes before the object it's built on.
        builder.ref_delta(middle_id, &delta_appending(&middle, b"last\n"));
        let base_id = builder.blob(&base);
        builder.ref_delta(base_id, &delta_appending(&base, b"middle\n"));

        let root = builder.tree(&[("100644", b"f", object_id(ObjectKind::Blob, &last))]);
        let commit = builder.commit(root);

        assert_eq!(read_ok(&builder.finish(), commit).files[0].1, last);
    }

    #[test]
    fn folders_can_be_stored_as_changes_too() {
        let mut builder = PackBuilder::default();
        let a = builder.blob(b"a");
        let first = tree_bytes(&[("100644", b"a", a)]);
        let second = tree_bytes(&[("100644", b"a", a), ("100644", b"b", a)]);
        let first_id = builder.whole(ObjectKind::Tree, &first);
        builder.ref_delta(first_id, &delta_appending(&first, &second[first.len()..]));
        let commit = builder.commit(object_id(ObjectKind::Tree, &second));

        assert_eq!(read_ok(&builder.finish(), commit).files.len(), 2);
    }

    #[test]
    fn large_files_are_listed_instead_of_read() {
        let (pack, commit) = {
            let mut builder = PackBuilder::default();
            let big = builder.blob(&[0; 100]);
            let small = builder.blob(b"x");
            let root = builder.tree(&[("100644", b"big.bin", big), ("100644", b"small", small)]);
            let commit = builder.commit(root);
            (builder.finish(), commit)
        };
        let limits = Limits {
            max_file_bytes: 50,
            ..Limits::default()
        };

        let read = read_with(&pack, commit, &limits).unwrap();

        assert_eq!(read.files.len(), 1);
        assert_eq!(read.summary.skipped_total, 1);
        assert_eq!(read.summary.skipped[0].size, 100);
        assert_eq!(read.summary.skipped[0].path.raw(), "big.bin");
    }

    #[test]
    fn lists_links_and_submodules() {
        let mut builder = PackBuilder::default();
        let target = builder.blob(b"../../.ssh/id_rsa");
        let pinned = [7; ID_BYTES];
        let root = builder.tree(&[("120000", b"link", target), ("160000", b"lib", pinned)]);
        let commit = builder.commit(root);

        let read = read_ok(&builder.finish(), commit);

        assert!(read.files.is_empty());
        assert_eq!(read.summary.links[0].path.raw(), "link");
        assert_eq!(read.summary.links[0].target.raw(), "../../.ssh/id_rsa");
        assert_eq!(read.summary.submodules[0].path.raw(), "lib");
        assert_eq!(read.summary.submodules[0].commit, hex_id(&pinned));
    }

    #[test]
    fn a_hostile_file_name_stays_escaped() {
        let mut builder = PackBuilder::default();
        let blob = builder.blob(b"x");
        let root = builder.tree(&[("100644", b"a\x1b[2J\xff", blob)]);
        let commit = builder.commit(root);

        let read = read_ok(&builder.finish(), commit);

        assert!(read.files[0].0.contains('\x1b'));
        assert!(
            !Untrusted::from_bytes(read.files[0].0.as_bytes())
                .to_string()
                .contains('\x1b')
        );
    }

    fn expect_error(result: Result<Read, GitError>) -> GitError {
        match result {
            Ok(_) => panic!("expected this to be refused"),
            Err(error) => error,
        }
    }

    #[test]
    fn a_commit_that_is_not_in_the_pack_is_an_error() {
        let (pack, _) = sample_pack();

        let error = expect_error(read_with(&pack, [9; ID_BYTES], &Limits::default()));

        assert!(matches!(error, GitError::Missing(_)), "{error}");
    }

    #[test]
    fn asking_for_something_that_is_not_a_commit_is_an_error() {
        let mut builder = PackBuilder::default();
        let blob = builder.blob(b"x");

        let error = expect_error(read_with(&builder.finish(), blob, &Limits::default()));

        assert!(matches!(error, GitError::Malformed(_)), "{error}");
    }

    #[test]
    fn files_missing_from_the_pack_are_an_error_not_a_gap() {
        let mut builder = PackBuilder::default();
        let root = builder.tree(&[("100644", b"hidden.js", [9; ID_BYTES])]);
        let commit = builder.commit(root);

        let error = expect_error(read_with(&builder.finish(), commit, &Limits::default()));

        assert!(matches!(error, GitError::Missing(_)), "{error}");
    }

    #[test]
    fn a_file_with_the_wrong_contents_cannot_pass_for_the_real_one() {
        let mut builder = PackBuilder::default();
        // The folder names a file by its hash, and a different file is what's sent.
        builder.blob(b"harmless\n");
        let root = builder.tree(&[("100644", b"a.js", object_id(ObjectKind::Blob, b"evil\n"))]);
        let commit = builder.commit(root);

        let error = expect_error(read_with(&builder.finish(), commit, &Limits::default()));

        assert!(matches!(error, GitError::Missing(_)), "{error}");
    }

    #[test]
    fn refuses_a_pack_that_fails_its_checksum() {
        let (mut pack, commit) = sample_pack();
        let middle = pack.len() / 2;
        pack[middle] ^= 1;

        let error = expect_error(read_with(&pack, commit, &Limits::default()));

        assert!(matches!(error, GitError::Malformed(_)), "{error}");
    }

    #[test]
    fn refuses_broken_packs_without_panicking() {
        let (pack, commit) = sample_pack();

        let with_checksum = |mut body: Vec<u8>| {
            let digest = Sha1::digest(&body);
            body.extend_from_slice(&digest);
            body
        };
        let cases = [
            Vec::new(),
            b"PACK".to_vec(),
            pack[..pack.len() / 2].to_vec(),
            with_checksum(b"PACK\0\0\0\x02\0\0\0\x01".to_vec()),
            with_checksum(b"PACK\0\0\0\x09\0\0\0\0".to_vec()),
            with_checksum(b"NOPE\0\0\0\x02\0\0\0\0".to_vec()),
            // Says it has more objects than it does.
            with_checksum(b"PACK\0\0\0\x02\xff\xff\xff\xff".to_vec()),
            // A reserved object type.
            with_checksum(b"PACK\0\0\0\x02\0\0\0\x01\x50\0".to_vec()),
            // A size that never ends.
            with_checksum([b"PACK\0\0\0\x02\0\0\0\x01".as_slice(), &[0xff; 40]].concat()),
            // An offset past the start of the pack.
            with_checksum(b"PACK\0\0\0\x02\0\0\0\x01\x60\x7f".to_vec()),
        ];

        for (index, case) in cases.iter().enumerate() {
            let result = read_with(case, commit, &Limits::default());

            assert!(result.is_err(), "case {index}");
        }
    }

    #[test]
    fn extra_data_after_the_last_object_is_refused() {
        let mut builder = PackBuilder::default();
        builder.blob(b"x");
        builder.body.extend_from_slice(b"junk");

        let error = expect_error(read_with(
            &builder.finish(),
            [0; ID_BYTES],
            &Limits::default(),
        ));

        assert!(matches!(error, GitError::Malformed(_)), "{error}");
    }

    #[test]
    fn refuses_an_object_larger_than_it_says() {
        let mut builder = PackBuilder::default();
        builder.entry_header(3, 4);
        builder
            .body
            .extend_from_slice(&deflate(&vec![0; 1024 * 1024]));
        builder.count += 1;

        let error = expect_error(read_with(
            &builder.finish(),
            [0; ID_BYTES],
            &Limits::default(),
        ));

        assert!(matches!(error, GitError::Malformed(_)), "{error}");
    }

    #[test]
    fn refuses_an_object_smaller_than_it_says() {
        let mut builder = PackBuilder::default();
        builder.entry_header(3, 400);
        builder.body.extend_from_slice(&deflate(b"short"));
        builder.count += 1;

        let error = expect_error(read_with(
            &builder.finish(),
            [0; ID_BYTES],
            &Limits::default(),
        ));

        assert!(matches!(error, GitError::Malformed(_)), "{error}");
    }

    #[test]
    fn a_decompression_bomb_hits_the_work_limit() {
        let mut builder = PackBuilder::default();
        let big = vec![0; 10 * 1024 * 1024];
        let commit = builder.commit([1; ID_BYTES]);
        for _ in 0..3 {
            builder.blob(&big);
        }
        let limits = Limits {
            max_work_bytes: 1024 * 1024,
            ..Limits::default()
        };

        let error = expect_error(read_with(&builder.finish(), commit, &limits));

        assert!(matches!(error, GitError::WorkTooLarge), "{error}");
    }

    #[test]
    fn a_change_claiming_a_huge_result_is_refused_before_building_it() {
        let base = b"base";
        let mut delta = Vec::new();
        write_delta_size(&mut delta, base.len() as u64);
        write_delta_size(&mut delta, 1 << 50);

        assert!(matches!(
            apply_delta(base, &delta, 1024),
            Err(GitError::ObjectTooLarge)
        ));
    }

    #[test]
    fn broken_changes_are_refused() {
        let base = b"base text";
        let sizes = |result: u64| {
            let mut delta = Vec::new();
            write_delta_size(&mut delta, base.len() as u64);
            write_delta_size(&mut delta, result);
            delta
        };

        for (name, delta) in [
            ("empty", Vec::new()),
            ("wrong base size", {
                let mut delta = Vec::new();
                write_delta_size(&mut delta, 1);
                write_delta_size(&mut delta, 1);
                delta
            }),
            ("reserved instruction", [sizes(1), vec![0]].concat()),
            (
                "copy past the end",
                [sizes(9), vec![0x90 | 1, 200, 9]].concat(),
            ),
            ("cut off copy", [sizes(9), vec![0x90 | 1]].concat()),
            ("cut off insert", [sizes(5), vec![5, b'a']].concat()),
            ("too short", [sizes(50), vec![1, b'a']].concat()),
            ("too long", [sizes(1), vec![2, b'a', b'b']].concat()),
            ("offset overflow", [sizes(9), vec![0xff; 12]].concat()),
        ] {
            assert!(apply_delta(base, &delta, 1024).is_err(), "{name}");
        }
    }

    #[test]
    fn copies_of_the_default_size_work() {
        let base = vec![5; 0x10000];
        let mut delta = Vec::new();
        write_delta_size(&mut delta, base.len() as u64);
        write_delta_size(&mut delta, base.len() as u64);
        delta.push(0x80);

        assert_eq!(apply_delta(&base, &delta, 1 << 20).unwrap(), base);
    }

    #[test]
    fn objects_built_on_each_other_in_a_circle_are_refused_if_needed() {
        let id_a = [1; ID_BYTES];
        let id_b = [2; ID_BYTES];
        let mut builder = PackBuilder::default();
        builder.ref_delta(id_b, b"\0\0");
        builder.ref_delta(id_a, b"\0\0");
        let root = builder.tree(&[("100644", b"a", id_a)]);
        let commit = builder.commit(root);

        let error = expect_error(read_with(&builder.finish(), commit, &Limits::default()));

        assert!(matches!(error, GitError::Missing(_)), "{error}");
    }

    #[test]
    fn folders_repeating_inside_each_other_hit_the_entry_limit() {
        let mut builder = PackBuilder::default();
        let blob = builder.blob(b"x");
        let mut level = builder.tree(&[("100644", b"f", blob)]);
        // Ten of each of ten levels would be ten billion files, from a tiny pack.
        for _ in 0..10 {
            let names: Vec<Vec<u8>> = (0..10).map(|n| format!("d{n}").into_bytes()).collect();
            let entries: Vec<(&str, &[u8], [u8; ID_BYTES])> = names
                .iter()
                .map(|name| ("40000", name.as_slice(), level))
                .collect();
            level = builder.tree(&entries);
        }
        let commit = builder.commit(level);
        let pack = builder.finish();
        assert!(pack.len() < 10_000);

        let error = expect_error(read_with(&pack, commit, &Limits::default()));

        assert!(matches!(error, GitError::TooManyEntries { .. }), "{error}");
    }

    #[test]
    fn the_same_big_file_many_times_hits_the_read_limit() {
        let mut builder = PackBuilder::default();
        let blob = builder.blob(&[0; 1000]);
        let names: Vec<Vec<u8>> = (0..10).map(|n| format!("f{n}").into_bytes()).collect();
        let entries: Vec<(&str, &[u8], [u8; ID_BYTES])> = names
            .iter()
            .map(|name| ("100644", name.as_slice(), blob))
            .collect();
        let root = builder.tree(&entries);
        let commit = builder.commit(root);
        let limits = Limits {
            max_read_bytes: 5000,
            ..Limits::default()
        };

        let error = expect_error(read_with(&builder.finish(), commit, &limits));

        assert!(matches!(error, GitError::ReadTooLarge { .. }), "{error}");
    }

    #[test]
    fn folders_nested_absurdly_deep_are_refused_without_a_crash() {
        let mut builder = PackBuilder::default();
        let blob = builder.blob(b"x");
        let mut level = builder.tree(&[("100644", b"f", blob)]);
        for _ in 0..MAX_FOLDER_DEPTH + 2 {
            level = builder.tree(&[("40000", b"d", level)]);
        }
        let commit = builder.commit(level);

        let error = expect_error(read_with(&builder.finish(), commit, &Limits::default()));

        assert!(matches!(error, GitError::Malformed(_)), "{error}");
    }

    #[test]
    fn something_listed_as_the_wrong_type_is_refused() {
        let mut builder = PackBuilder::default();
        let blob = builder.blob(b"x");
        let root = builder.tree(&[("40000", b"not-a-folder", blob)]);
        let commit = builder.commit(root);
        assert!(read_with(&builder.finish(), commit, &Limits::default()).is_err());

        let mut builder = PackBuilder::default();
        let inner = builder.tree(&[]);
        let root = builder.tree(&[("100644", b"not-a-file", inner)]);
        let commit = builder.commit(root);
        assert!(read_with(&builder.finish(), commit, &Limits::default()).is_err());
    }

    #[test]
    fn broken_folders_are_refused() {
        for data in [
            &b"100644"[..],
            b"100644 name",
            b"100644 name\0short",
            b"zzz name\0aaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(parse_tree(data).is_err(), "{data:?}");
        }
    }

    fn pkt(data: &[u8]) -> Vec<u8> {
        let mut line = format!("{:04x}", data.len() + 4).into_bytes();
        line.extend_from_slice(data);
        line
    }

    fn band(number: u8, data: &[u8]) -> Vec<u8> {
        pkt(&[&[number], data].concat())
    }

    #[test]
    fn reads_the_pack_out_of_a_servers_answer() {
        let response = [
            pkt(b"shallow-info\n"),
            pkt(b"shallow 0123\n"),
            b"0001".to_vec(),
            pkt(b"packfile\n"),
            band(BAND_PROGRESS, b"counting\n"),
            band(BAND_PACK, b"PA"),
            band(BAND_PACK, b"CK"),
            b"0000".to_vec(),
        ]
        .concat();

        assert_eq!(
            read_response(response.as_slice(), &Limits::default()).unwrap(),
            b"PACK"
        );
    }

    #[test]
    fn says_what_the_server_objected_to_without_trusting_it() {
        for response in [
            pkt(b"ERR not our ref\x1b[2J\n"),
            [
                pkt(b"packfile\n"),
                band(BAND_ERROR, b"not our ref\x1b[2J\n"),
            ]
            .concat(),
        ] {
            let error = read_response(response.as_slice(), &Limits::default()).unwrap_err();

            assert!(matches!(&error, GitError::Host(text) if text.contains("not our ref")));
        }
    }

    #[test]
    fn an_answer_with_no_pack_is_an_error() {
        for response in [&b""[..], b"0000", b"0001"] {
            assert!(matches!(
                read_response(response, &Limits::default()),
                Err(GitError::Missing(_))
            ));
        }
    }

    #[test]
    fn unreadable_answers_are_refused() {
        for response in [
            &b"zzzz"[..],
            b"00",
            b"0003",
            b"ffff",
            b"0010short",
            b"0009packf",
        ] {
            assert!(
                read_response(response, &Limits::default()).is_err(),
                "{response:?}"
            );
        }

        let unknown_band = [pkt(b"packfile\n"), band(9, b"x")].concat();
        assert!(read_response(unknown_band.as_slice(), &Limits::default()).is_err());
    }

    #[test]
    fn a_download_past_the_limit_stops_there() {
        let response = [pkt(b"packfile\n"), band(BAND_PACK, &[0; 200])].concat();
        let limits = Limits {
            max_download_bytes: 100,
            ..Limits::default()
        };

        assert!(matches!(
            read_response(response.as_slice(), &limits),
            Err(GitError::DownloadTooLarge { .. })
        ));
    }

    #[test]
    fn asks_for_just_one_commit_with_no_history() {
        let body = request_body("abc");

        assert!(body.starts_with("0012command=fetch\n0001"));
        assert!(body.contains("deepen 1\n"));
        assert!(body.contains("want abc\n"));
        assert!(body.contains("done\n"));
        assert!(body.ends_with("0000"));
        assert!(!body.contains("thin-pack"));
    }

    #[test]
    #[ignore = "contacts the real hosts"]
    fn reads_a_real_commit_from_every_host() {
        use crate::source::Target;

        for url in [
            "https://github.com/octocat/Hello-World",
            "https://gitlab.com/gitlab-org/cli",
            "https://bitbucket.org/atlassian/aws-s3-deploy",
        ] {
            let target = Target::parse(url).unwrap();
            let resolved = crate::refs::resolve(&target.source, None).unwrap();
            let mut files = 0;

            read_commit(
                &target.source,
                &resolved.commit,
                None,
                &Limits::default(),
                |_| files += 1,
            )
            .unwrap();

            assert!(files > 0, "{url}");
        }
    }
}
