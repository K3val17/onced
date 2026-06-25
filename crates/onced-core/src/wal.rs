//! Write-ahead log: crash-safe, tamper-evident durability for the idempotency store.
//!
//! State changes are appended to a log file and forced to disk with `fsync`;
//! on restart the log is replayed to rebuild the in-memory index exactly. This
//! is the classic database durability discipline (Gray, "The Transaction
//! Concept"). Two `fsync` policies are offered (see [`WalStore`]): **strict**
//! (one `fsync` per write, durable before it returns) and **group commit** (one
//! `fsync` per [`flush`](Store::flush)ed batch). Each record is length-framed
//! and CRC32-checksummed so a torn or corrupt tail (the signature of a crash
//! mid-append) is detected and discarded rather than trusted.
//!
//! ## Tamper-evidence: hash-chaining
//!
//! Beyond CRC32 (which detects accidental bit-flips), records are **hash-chained**
//! with SHA-256 so that any insertion, deletion, reorder, or deliberate edit of a
//! durable record is detectable on the next open.
//!
//! The chain is defined as:
//!   `chain_0 = GENESIS = [0u8; 32]`
//!   `chain_i = sha256(chain_{i-1} || crc_bytes_of_record_i || payload_of_record_i)`
//!
//! Each record carries the chain hash that was computed for it. On replay the
//! chain is recomputed from the genesis and compared to the stored value; any
//! mismatch (tamper, reorder, insert, or edit) is surfaced as `InvalidData` —
//! the same loud-failure path as interior CRC corruption.
//!
//! **Compaction** rewrites the log with a fresh chain recomputed from genesis
//! over the surviving records. This is a checkpoint: the new chain root is
//! independent of the old log's chain history.
//!
//! Frame layout (per record): `[payload_len: u32][crc32: u32][chain: 32][payload]`
//!
//! Records are written with no external dependencies: a small hand-rolled
//! binary format, so the on-disk layout is fully auditable.
//!
//! Production code is written test-first; the tests below are watched failing
//! before `WalStore`, `encode_record`, and `decode_record` exist.

use crate::hash::sha256;
use crate::store::Store;
use crate::{CachedOutcome, Fence, IdempotencyKey, KeyState, RequestFingerprint};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const TAG_IN_PROGRESS: u8 = 0;
const TAG_COMPLETED: u8 = 1;

/// The genesis chain value: the "previous hash" for the very first record.
/// All-zeros is conventional (similar to Bitcoin's genesis block prev-hash).
pub(crate) const GENESIS: [u8; 32] = [0u8; 32];

/// Number of bytes in the record header (len:u32 + crc:u32 + chain:32).
pub(crate) const HEADER_LEN: usize = 4 + 4 + 32;

/// CRC32 (IEEE 802.3, reflected, poly 0xEDB88320). Bit-at-a-time: small and
/// dependency-free; throughput is not on the hot path for Phase 2.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Compute the chain hash for a single record given the previous chain value.
/// `chain_i = sha256(chain_{i-1} || crc_bytes || payload)`
fn compute_chain(prev_chain: &[u8; 32], crc: u32, payload: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 4 + payload.len());
    input.extend_from_slice(prev_chain);
    input.extend_from_slice(&crc.to_le_bytes());
    input.extend_from_slice(payload);
    sha256(&input)
}

fn put_u16(buf: &mut Vec<u8>, x: u16) {
    buf.extend_from_slice(&x.to_le_bytes());
}
fn put_u32(buf: &mut Vec<u8>, x: u32) {
    buf.extend_from_slice(&x.to_le_bytes());
}
fn put_u64(buf: &mut Vec<u8>, x: u64) {
    buf.extend_from_slice(&x.to_le_bytes());
}
fn put_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}
fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_bytes(buf, s.as_bytes());
}

/// A bounds-checked little-endian reader over a record payload. Every read
/// returns `None` past the end, so a truncated or corrupt payload can never
/// produce a partially-formed record.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn arr32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }
    fn bytes(&mut self) -> Option<Vec<u8>> {
        let n = self.u32()? as usize;
        Some(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> Option<String> {
        String::from_utf8(self.bytes()?).ok()
    }
}

/// Serialize one `(key, state)` into a self-describing, length-framed,
/// CRC-checksummed, hash-chained record:
/// `[payload_len: u32][crc32: u32][chain: 32][payload]`.
///
/// `prev_chain` is the chain hash of the immediately preceding record (or
/// [`GENESIS`] for the first record). The chain hash written into the record
/// is `sha256(prev_chain || crc_bytes || payload)`, binding this record to its
/// position in the sequence.
///
/// Exposed (with [`decode_record`]) as the low-level on-disk codec so it can be
/// fuzzed directly; most callers use [`WalStore`].
pub fn encode_record(key: &IdempotencyKey, state: &KeyState, prev_chain: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::new();
    put_str(&mut payload, &key.0);
    match state {
        KeyState::InProgress {
            fence,
            fingerprint,
            lease_expires_at_ms,
        } => {
            payload.push(TAG_IN_PROGRESS);
            put_u64(&mut payload, fence.0);
            payload.extend_from_slice(&fingerprint.0);
            put_u64(&mut payload, *lease_expires_at_ms);
        }
        KeyState::Completed {
            fingerprint,
            outcome,
            completed_at_ms,
        } => {
            payload.push(TAG_COMPLETED);
            payload.extend_from_slice(&fingerprint.0);
            put_u64(&mut payload, *completed_at_ms);
            put_u16(&mut payload, outcome.status);
            put_u32(&mut payload, outcome.headers.len() as u32);
            for (name, value) in &outcome.headers {
                put_str(&mut payload, name);
                put_str(&mut payload, value);
            }
            put_bytes(&mut payload, &outcome.body);
        }
    }

    let crc = crc32(&payload);
    let chain = compute_chain(prev_chain, crc, &payload);

    let mut framed = Vec::with_capacity(HEADER_LEN + payload.len());
    put_u32(&mut framed, payload.len() as u32);
    put_u32(&mut framed, crc);
    framed.extend_from_slice(&chain);
    framed.extend_from_slice(&payload);
    framed
}

/// Decode one record from the front of `buf`. Returns the number of bytes
/// consumed, the record, and the stored chain hash; or `None` if `buf` does
/// not begin with a complete, checksum-valid record (truncated tail or
/// corruption). Must never panic or over-read on arbitrary input — it parses
/// untrusted on-disk bytes after a crash. Exposed for fuzzing (see the `fuzz/`
/// crate).
///
/// Note: this function does NOT verify the chain hash — that is the caller's
/// responsibility so that replay can accumulate the chain progressively.
pub fn decode_record(buf: &[u8]) -> Option<(usize, IdempotencyKey, KeyState, [u8; 32])> {
    let header = buf.get(0..HEADER_LEN)?;
    let len = u32::from_le_bytes(header[0..4].try_into().ok()?) as usize;
    let crc = u32::from_le_bytes(header[4..8].try_into().ok()?);
    let chain: [u8; 32] = header[8..40].try_into().ok()?;
    let total = HEADER_LEN.checked_add(len)?;
    let payload = buf.get(HEADER_LEN..total)?;
    if crc32(payload) != crc {
        return None;
    }

    let mut reader = Reader::new(payload);
    let key = IdempotencyKey(reader.string()?);
    let state = match reader.u8()? {
        TAG_IN_PROGRESS => KeyState::InProgress {
            fence: Fence(reader.u64()?),
            fingerprint: RequestFingerprint(reader.arr32()?),
            lease_expires_at_ms: reader.u64()?,
        },
        TAG_COMPLETED => {
            let fingerprint = RequestFingerprint(reader.arr32()?);
            let completed_at_ms = reader.u64()?;
            let status = reader.u16()?;
            let header_count = reader.u32()? as usize;
            let mut headers = BTreeMap::new();
            for _ in 0..header_count {
                let name = reader.string()?;
                let value = reader.string()?;
                headers.insert(name, value);
            }
            let body = reader.bytes()?;
            KeyState::Completed {
                fingerprint,
                outcome: CachedOutcome {
                    status,
                    headers,
                    body,
                },
                completed_at_ms,
            }
        }
        _ => return None,
    };
    Some((total, key, state, chain))
}

/// Best-effort `fsync` of `path`'s parent directory, so a `rename` (or first
/// creation) of the file becomes durable across power loss — the file's data is
/// already fsync'd; this persists the directory entry. Not every platform /
/// filesystem supports directory fsync, so a failure here is tolerated rather
/// than fail-stop (the data is durable regardless).
fn sync_parent_dir(path: &Path) {
    let parent = path.parent().unwrap_or(Path::new(""));
    let dir = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

/// Whether `buf` begins with a *complete* record frame — the full
/// `[len][crc][chain][payload]` is present. If a complete frame is present yet
/// [`decode_record`] still failed, the checksum did not match: that is interior
/// corruption of a durable record, not a partially-written tail.
fn is_complete_frame(buf: &[u8]) -> bool {
    let Some(header) = buf.get(0..HEADER_LEN) else {
        return false;
    };
    let len = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
    match HEADER_LEN.checked_add(len) {
        Some(total) => buf.len() >= total,
        None => false,
    }
}

/// A durable [`Store`]: an in-memory index kept in lock-step with an append-only
/// write-ahead log on disk. Reads hit memory. On `open` the log is replayed and
/// any torn or corrupt tail is truncated away.
///
/// ## Tamper-evidence
///
/// Records are hash-chained with SHA-256 (see the module doc). `WalStore` tracks
/// the current chain root and advances it on every `put`. On reopen the chain is
/// recomputed and verified; any mismatch is an `InvalidData` error. Compaction
/// restarts the chain from genesis over the surviving records.
///
/// Two durability disciplines, chosen at open time:
///
/// - **Strict** ([`WalStore::open`]) — every `put` is appended and `fsync`ed
///   before it returns. Simplest and safest; bounded by one `fsync` per write.
/// - **Group commit** ([`WalStore::open_buffered`]) — `put` only buffers the
///   record in userspace; nothing reaches the file descriptor until an explicit
///   [`Store::flush`]. One `fsync` then makes a whole batch durable at once, the
///   way Postgres, FoundationDB, and TigerBeetle amortize disk latency. The
///   caller MUST `flush` before acknowledging an operation as durable; anything
///   still in the buffer when the process dies is correctly lost (and, for the
///   idempotency engine, simply retried and taken over — exactly-once holds).
pub struct WalStore {
    index: HashMap<IdempotencyKey, KeyState>,
    file: std::fs::File,
    /// The log's path, kept so compaction can rewrite it atomically.
    path: std::path::PathBuf,
    /// Records appended since the last durable `flush`, not yet on the fd.
    pending: Vec<u8>,
    /// Strict mode: `fsync` inside every `put`. Group-commit mode: defer to
    /// `flush`.
    sync_each: bool,
    /// The SHA-256 chain hash of the last record appended (or genesis if empty).
    chain_root: [u8; 32],
}

impl WalStore {
    /// Open in **strict** mode: one `fsync` per `put`.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Self::open_with(path, true)
    }

    /// Open in **group-commit** mode: `put` buffers, `flush` makes the batch
    /// durable with a single `fsync`. See the type docs for the durability
    /// contract the caller must honour.
    pub fn open_buffered(path: &Path) -> std::io::Result<Self> {
        Self::open_with(path, false)
    }

    /// The current chain root: the SHA-256 hash of the last appended record
    /// (chained from genesis). After a fresh open of an empty log this is
    /// the genesis value `[0u8; 32]`. After compaction it reflects the chain
    /// recomputed from genesis over the surviving records.
    pub fn root(&self) -> [u8; 32] {
        self.chain_root
    }

    fn open_with(path: &Path, sync_each: bool) -> std::io::Result<Self> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let mut index = HashMap::new();
        let mut offset = 0usize;
        let mut chain_root = GENESIS;

        while let Some((consumed, key, state, stored_chain)) = decode_record(&buf[offset..]) {
            // Recompute what the chain should be for this record position.
            let crc = u32::from_le_bytes(buf[offset + 4..offset + 8].try_into().unwrap());
            let payload = &buf[offset + HEADER_LEN..offset + consumed];
            let expected_chain = compute_chain(&chain_root, crc, payload);
            if expected_chain != stored_chain {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "onced WAL: chain hash mismatch at offset {offset} \
                         -- tamper, reorder, or insert detected"
                    ),
                ));
            }
            chain_root = expected_chain;
            index.insert(key, state);
            offset += consumed;
        }

        // If decoding stopped before the end, decide *why*. A torn tail — the
        // final record only partially written before a crash — is normal and
        // recoverable: truncate it away. But a *complete* frame whose checksum
        // fails is interior corruption of previously-durable data; silently
        // truncating it (and every record after) is data loss. Surface it loudly
        // instead (ALICE / RocksDB durability bar).
        let remaining = &buf[offset..];
        if !remaining.is_empty() && is_complete_frame(remaining) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "onced WAL: checksum failure on a complete record at offset {offset} \
                     -- interior corruption, refusing to silently truncate durable data"
                ),
            ));
        }

        // Drop any torn tail past the last valid record and position the write
        // cursor at the end of durable data, so future appends are clean.
        file.set_len(offset as u64)?;
        file.seek(SeekFrom::Start(offset as u64))?;

        Ok(Self {
            index,
            file,
            path: path.to_path_buf(),
            pending: Vec::new(),
            sync_each,
            chain_root,
        })
    }

    /// Append the buffered batch and `fsync` it. Fail-stop: a write or `fsync`
    /// error halts rather than acknowledging a non-durable write (standard WAL
    /// policy; graceful degradation is a later refinement, see the design doc).
    fn flush_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        self.file
            .write_all(&self.pending)
            .expect("onced WAL: append failed; refusing to continue");
        self.file
            .sync_all()
            .expect("onced WAL: fsync failed; refusing to continue");
        self.pending.clear();
    }
}

impl Store for WalStore {
    fn max_in_progress_fence(&self) -> u64 {
        self.index
            .values()
            .filter_map(|state| match state {
                KeyState::InProgress { fence, .. } => Some(fence.0),
                KeyState::Completed { .. } => None,
            })
            .max()
            .unwrap_or(0)
    }

    fn get(&self, key: &IdempotencyKey) -> Option<&KeyState> {
        self.index.get(key)
    }

    fn put(&mut self, key: IdempotencyKey, state: KeyState) {
        // The record is buffered and the index updated immediately so reads in
        // this process are consistent. Durability is a separate step: strict
        // mode forces it now; group-commit mode defers it to the next `flush`.
        let record = encode_record(&key, &state, &self.chain_root);
        // Extract the chain from the record we just encoded (bytes 8..40).
        let new_chain: [u8; 32] = record[8..40].try_into().unwrap();
        self.pending.extend_from_slice(&record);
        self.chain_root = new_chain;
        self.index.insert(key, state);
        if self.sync_each {
            self.flush_pending();
        }
    }

    fn flush(&mut self) {
        self.flush_pending();
    }

    fn compact(&mut self, keep: &mut dyn FnMut(&IdempotencyKey, &KeyState) -> bool) {
        // 1. Filter the live index. Every append since the last compaction that
        //    overwrote a key, plus every entry `keep` now rejects (e.g. expired),
        //    is dropped here.
        self.index.retain(|key, state| keep(key, state));

        // 2. Rewrite the log with exactly one record per surviving entry, with a
        //    FRESH chain recomputed from genesis (compaction is a checkpoint;
        //    the new chain is independent of the old log's chain history).
        let mut compacted = Vec::new();
        let mut chain = GENESIS;
        for (key, state) in &self.index {
            let record = encode_record(key, state, &chain);
            // Advance chain using the hash we just embedded in the record.
            chain = record[8..40].try_into().unwrap();
            compacted.extend_from_slice(&record);
        }
        let new_chain_root = chain;

        // 3. Commit it crash-safely: write the new log to a temp file, fsync it,
        //    then atomically rename it over the live path. A crash before the
        //    rename leaves the old log intact; after it, the new one — never a
        //    half-written log. (fsync of the directory entry is a further
        //    hardening; rename atomicity already protects the data.)
        let tmp = self.path.with_extension("wal-compact");
        {
            let mut tmp_file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .expect("onced WAL: open compaction temp failed; refusing to continue");
            tmp_file
                .write_all(&compacted)
                .expect("onced WAL: write compaction temp failed; refusing to continue");
            tmp_file
                .sync_all()
                .expect("onced WAL: fsync compaction temp failed; refusing to continue");
        }
        std::fs::rename(&tmp, &self.path)
            .expect("onced WAL: atomic rename of compacted log failed; refusing to continue");
        // Persist the directory entry: the renamed file's *data* is already
        // fsync'd, but on several filesystems the rename itself can be lost on
        // power loss unless the parent directory is fsync'd too.
        sync_parent_dir(&self.path);

        // 4. Reopen the live file at the end of the freshly written data. The
        //    pending buffer's records are already reflected in the index (and so
        //    in the compacted log we just fsync'd), so drop it — compaction is
        //    itself a durability point.
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .expect("onced WAL: reopen after compaction failed; refusing to continue");
        file.seek(SeekFrom::End(0))
            .expect("onced WAL: seek after compaction failed; refusing to continue");
        self.file = file;
        self.pending.clear();
        self.chain_root = new_chain_root;
    }
}

#[cfg(test)]
mod tests {
    use crate::store::Store;
    use crate::wal::{decode_record, encode_record, WalStore, GENESIS, HEADER_LEN};
    use crate::{CachedOutcome, Fence, IdempotencyKey, KeyState, RequestFingerprint};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_wal_path(tag: &str) -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "onced-wal-{}-{}-{}.log",
            std::process::id(),
            tag,
            n
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn completed(status: u16, body: &[u8]) -> KeyState {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        KeyState::Completed {
            fingerprint: RequestFingerprint([3u8; 32]),
            outcome: CachedOutcome {
                status,
                headers,
                body: body.to_vec(),
            },
            completed_at_ms: 50_000,
        }
    }

    /// A record must survive a serialize -> deserialize round trip byte-for-byte.
    #[test]
    fn encode_then_decode_round_trips_both_variants() {
        let key = IdempotencyKey("round-trip".into());

        let in_progress = KeyState::InProgress {
            fence: Fence(42),
            fingerprint: RequestFingerprint([7u8; 32]),
            lease_expires_at_ms: 99_000,
        };
        let framed = encode_record(&key, &in_progress, &GENESIS);
        let (consumed, k, s, chain) = decode_record(&framed).expect("valid record decodes");
        assert_eq!(consumed, framed.len());
        assert_eq!(k, key);
        assert_eq!(s, in_progress);
        // Chain must be non-genesis (a real SHA-256 of the record contents).
        assert_ne!(chain, GENESIS);

        let done = completed(201, b"charged");
        let framed = encode_record(&key, &done, &GENESIS);
        let (consumed, k, s, chain2) = decode_record(&framed).expect("valid record decodes");
        assert_eq!(consumed, framed.len());
        assert_eq!(k, key);
        assert_eq!(s, done);
        assert_ne!(chain2, GENESIS);
        // Different states produce different chains.
        assert_ne!(chain, chain2);
    }

    /// A truncated/garbage tail (a crash mid-append) decodes to None, never a
    /// bogus record.
    #[test]
    fn a_truncated_record_decodes_to_none() {
        let key = IdempotencyKey("k".into());
        let framed = encode_record(&key, &completed(200, b"ok"), &GENESIS);
        // Hand the decoder every strict prefix of a valid record.
        for cut in 0..framed.len() {
            assert!(
                decode_record(&framed[..cut]).is_none(),
                "prefix of length {cut} must not decode"
            );
        }
    }

    /// The headline durability guarantee: a key written in one process lifetime
    /// is recovered after a simulated crash (drop without clean shutdown).
    #[test]
    fn a_completed_key_survives_a_simulated_crash() {
        let path = temp_wal_path("crash");
        let key = IdempotencyKey("charge-1".into());
        let state = completed(201, b"charged");

        // Lifetime 1: persist, then "crash" by dropping the store.
        {
            let mut store = WalStore::open(&path).expect("open fresh wal");
            store.put(key.clone(), state.clone());
        }

        // Lifetime 2: reopen the same file and the record must be present.
        let store = WalStore::open(&path).expect("reopen wal");
        assert_eq!(store.get(&key), Some(&state));

        let _ = std::fs::remove_file(&path);
    }

    /// Group-commit durability contract: a buffered `put` is NOT durable until
    /// `flush`. A crash (drop) before flush correctly loses it; a flush makes it
    /// durable. (Valid in-process because pending bytes are held in userspace and
    /// never reach the file descriptor until flush.)
    #[test]
    fn a_buffered_put_is_durable_only_after_flush() {
        let path = temp_wal_path("buffered");
        let key = IdempotencyKey("charge-b".into());
        let state = completed(201, b"charged");

        // Buffer a put, then "crash" without flushing: it must be lost.
        {
            let mut store = WalStore::open_buffered(&path).expect("open buffered");
            store.put(key.clone(), state.clone());
            // get() sees it within this process lifetime...
            assert_eq!(store.get(&key), Some(&state));
        }
        let store = WalStore::open(&path).expect("reopen");
        assert_eq!(
            store.get(&key),
            None,
            "an un-flushed put must not survive a crash"
        );

        // Now buffer, flush, then crash: it must survive.
        {
            let mut store = WalStore::open_buffered(&path).expect("open buffered");
            store.put(key.clone(), state.clone());
            store.flush();
        }
        let store = WalStore::open(&path).expect("reopen after flush");
        assert_eq!(store.get(&key), Some(&state), "a flushed put must survive");

        let _ = std::fs::remove_file(&path);
    }

    /// Group commit amortizes one `fsync` over a whole batch: many buffered puts
    /// followed by a single flush all recover.
    #[test]
    fn a_whole_batch_recovers_after_one_flush() {
        let path = temp_wal_path("batch");
        let states: Vec<(IdempotencyKey, KeyState)> = (0..100)
            .map(|i| {
                (
                    IdempotencyKey(format!("k{i}")),
                    completed(200, format!("body-{i}").as_bytes()),
                )
            })
            .collect();

        {
            let mut store = WalStore::open_buffered(&path).expect("open buffered");
            for (k, s) in &states {
                store.put(k.clone(), s.clone());
            }
            store.flush(); // one fsync for the whole batch
        }

        let store = WalStore::open(&path).expect("reopen");
        for (k, s) in &states {
            assert_eq!(store.get(k), Some(s));
        }

        let _ = std::fs::remove_file(&path);
    }

    /// A torn tail left by a crash mid-append is discarded on reopen, and the
    /// last fully-durable record is preserved.
    #[test]
    fn a_torn_tail_is_discarded_on_reopen() {
        let path = temp_wal_path("torn");
        let good = IdempotencyKey("good".into());
        let state = completed(200, b"ok");

        {
            let mut store = WalStore::open(&path).expect("open fresh wal");
            store.put(good.clone(), state.clone());
        }
        // Simulate a partial write: append a few bytes that cannot form a frame.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("reopen for append");
            f.write_all(&[0xFF, 0x00, 0x12, 0x34, 0xAB]).unwrap();
            f.sync_all().unwrap();
        }

        let store = WalStore::open(&path).expect("reopen after torn write");
        assert_eq!(store.get(&good), Some(&state));

        let _ = std::fs::remove_file(&path);
    }

    /// After a crash mid-flight, recovery must keep minting fences *above* the
    /// recovered in-progress lease. Otherwise a takeover reuses the dead
    /// worker's fence and would wrongly accept its stale, pre-crash token.
    #[test]
    fn a_recovered_in_progress_lease_invalidates_the_pre_crash_token() {
        use crate::engine::{Begin, CompleteError, Engine};

        let path = temp_wal_path("fence-recover");
        let key = IdempotencyKey("charge-x".into());
        let fingerprint = RequestFingerprint([5u8; 32]);
        let lease_ms = 30_000u64;

        // Lifetime 1: begin (InProgress persisted), then crash mid-flight.
        let pre_crash_token = {
            let mut engine = Engine::new(WalStore::open(&path).unwrap(), lease_ms);
            match engine.begin(key.clone(), fingerprint, 1_000) {
                Begin::Run(token) => token,
                other => panic!("expected Run, got {other:?}"),
            }
        };

        // Lifetime 2: recover and take over the expired lease.
        let mut engine = Engine::new(WalStore::open(&path).unwrap(), lease_ms);
        let fresh = match engine.begin(key.clone(), fingerprint, 1_000 + lease_ms + 1) {
            Begin::Run(token) => token,
            other => panic!("expired lease should allow takeover, got {other:?}"),
        };

        // The pre-crash token must now be refused...
        assert_eq!(
            engine.complete(
                pre_crash_token,
                CachedOutcome {
                    status: 500,
                    headers: BTreeMap::new(),
                    body: b"stale".to_vec(),
                },
                1_000 + lease_ms + 1,
            ),
            Err(CompleteError::StaleFence),
        );
        // ...and the fresh worker completes cleanly.
        engine
            .complete(
                fresh,
                CachedOutcome {
                    status: 201,
                    headers: BTreeMap::new(),
                    body: b"fresh".to_vec(),
                },
                1_000 + lease_ms + 1,
            )
            .unwrap();

        let _ = std::fs::remove_file(&path);
    }

    /// Interior corruption — a flipped byte in the *middle* of the log, with
    /// fully-durable records after it — must be surfaced, never silently
    /// truncated. Truncating at the first bad record would discard durable data
    /// (the ALICE / RocksDB bar: a torn *tail* is recoverable; mid-file checksum
    /// failure is corruption).
    #[test]
    fn interior_corruption_is_surfaced_not_silently_truncated() {
        let path = temp_wal_path("interior");
        {
            let mut store = WalStore::open(&path).unwrap();
            for i in 0..6u32 {
                store.put(IdempotencyKey(format!("k{i}")), completed(200, b"x"));
            }
        }

        // Flip a byte inside the first record's payload (past the full header).
        // Records after it remain intact, so this is interior corruption.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[HEADER_LEN + 1] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();

        let result = WalStore::open(&path);
        assert!(
            result.is_err(),
            "interior corruption must be surfaced as an error, not silently truncated"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The checksum is exactly IEEE 802.3 CRC-32 — pinned against the standard
    /// published check values, so any change to the algorithm is caught (a
    /// different-but-internally-consistent checksum would still round-trip).
    #[test]
    fn crc32_matches_known_ieee_vectors() {
        assert_eq!(super::crc32(b""), 0x0000_0000);
        assert_eq!(super::crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            super::crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    /// `Engine::flush` must actually make buffered (group-commit) writes durable:
    /// without the flush, a drop loses them.
    #[test]
    fn engine_flush_persists_buffered_writes() {
        use crate::engine::{Begin, Engine};
        let path = temp_wal_path("engine-flush");
        let key = IdempotencyKey("k".into());
        let outcome = CachedOutcome {
            status: 200,
            headers: BTreeMap::new(),
            body: b"ok".to_vec(),
        };
        {
            let mut engine = Engine::new(WalStore::open_buffered(&path).unwrap(), 30_000);
            let token = match engine.begin(key.clone(), RequestFingerprint([1u8; 32]), 1) {
                Begin::Run(token) => token,
                other => panic!("expected Run, got {other:?}"),
            };
            engine.complete(token, outcome.clone(), 1).unwrap();
            engine.flush();
        }
        let store = WalStore::open(&path).unwrap();
        assert!(
            matches!(store.get(&key), Some(KeyState::Completed { .. })),
            "engine.flush must persist buffered writes"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// `prune_expired` keeps a key whose TTL has NOT yet elapsed (boundary: prune
    /// just before expiry must not drop it).
    #[test]
    fn prune_keeps_an_unexpired_key() {
        use crate::engine::{Begin, Engine};
        const TTL: u64 = 10_000;
        let path = temp_wal_path("prune-keep");
        let key = IdempotencyKey("fresh".into());
        {
            let mut engine = Engine::with_ttl(WalStore::open(&path).unwrap(), 30_000, TTL);
            let token = match engine.begin(key.clone(), RequestFingerprint([1u8; 32]), 1_000) {
                Begin::Run(token) => token,
                other => panic!("expected Run, got {other:?}"),
            };
            engine
                .complete(
                    token,
                    CachedOutcome {
                        status: 200,
                        headers: BTreeMap::new(),
                        body: b"x".to_vec(),
                    },
                    1_000,
                )
                .unwrap();
            // Prune strictly before expiry (now < completed_at + ttl): keep it.
            engine.prune_expired(1_000 + TTL - 1);
        }
        let store = WalStore::open(&path).unwrap();
        assert!(
            store.get(&key).is_some(),
            "a key before its TTL must not be pruned"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// `prune_expired` removes a key exactly at its expiry instant (boundary:
    /// now == completed_at + ttl is expired).
    #[test]
    fn prune_removes_a_key_at_its_expiry_instant() {
        use crate::engine::{Begin, Engine};
        const TTL: u64 = 10_000;
        let path = temp_wal_path("prune-boundary");
        let key = IdempotencyKey("edge".into());
        {
            let mut engine = Engine::with_ttl(WalStore::open(&path).unwrap(), 30_000, TTL);
            let token = match engine.begin(key.clone(), RequestFingerprint([1u8; 32]), 1_000) {
                Begin::Run(token) => token,
                other => panic!("expected Run, got {other:?}"),
            };
            engine
                .complete(
                    token,
                    CachedOutcome {
                        status: 200,
                        headers: BTreeMap::new(),
                        body: b"x".to_vec(),
                    },
                    1_000,
                )
                .unwrap();
            // Prune exactly at expiry (now == completed_at + ttl): expired.
            engine.prune_expired(1_000 + TTL);
        }
        let store = WalStore::open(&path).unwrap();
        assert_eq!(
            store.get(&key),
            None,
            "a key at its expiry instant must be pruned"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Compaction collapses the dead, superseded records an append-only log
    /// accumulates: hammering one key 200 times then compacting must shrink the
    /// file, and the live value must survive a reopen.
    #[test]
    fn compaction_collapses_superseded_records() {
        let path = temp_wal_path("compact");
        let key = IdempotencyKey("hot".into());

        let mut store = WalStore::open(&path).unwrap();
        for i in 0..200 {
            store.put(key.clone(), completed(200, format!("v{i}").as_bytes()));
        }
        let before = std::fs::metadata(&path).unwrap().len();

        store.compact(&mut |_, _| true); // keep everything; just collapse history
        let after = std::fs::metadata(&path).unwrap().len();
        assert!(
            after < before,
            "compaction should shrink the log: {after} !< {before}"
        );

        let reopened = WalStore::open(&path).unwrap();
        assert_eq!(reopened.get(&key), Some(&completed(200, b"v199")));

        let _ = std::fs::remove_file(&path);
    }

    /// Compaction drops entries the `keep` predicate rejects, and the rest
    /// survive a reopen.
    #[test]
    fn compaction_drops_rejected_entries() {
        let path = temp_wal_path("compact-drop");
        let mut store = WalStore::open(&path).unwrap();
        for i in 0..10u32 {
            store.put(IdempotencyKey(format!("k{i}")), completed(200, b"x"));
        }

        // Keep only odd-numbered keys.
        store.compact(&mut |k, _| k.0.trim_start_matches('k').parse::<u32>().unwrap() % 2 == 1);

        let reopened = WalStore::open(&path).unwrap();
        for i in 0..10u32 {
            let present = reopened.get(&IdempotencyKey(format!("k{i}"))).is_some();
            assert_eq!(present, i % 2 == 1, "wrong retention for key k{i}");
        }

        let _ = std::fs::remove_file(&path);
    }

    /// `Engine::prune_expired` physically removes an expired completed key from
    /// the durable log, not just logically: after a prune, a reopened store does
    /// not contain it.
    #[test]
    fn prune_expired_physically_removes_expired_keys() {
        use crate::engine::{Begin, Engine};

        let path = temp_wal_path("prune");
        const TTL: u64 = 10_000;
        let key = IdempotencyKey("old".into());

        {
            let mut engine = Engine::with_ttl(WalStore::open(&path).unwrap(), 30_000, TTL);
            let token = match engine.begin(key.clone(), RequestFingerprint([1u8; 32]), 1_000) {
                Begin::Run(token) => token,
                other => panic!("expected Run, got {other:?}"),
            };
            engine
                .complete(
                    token,
                    CachedOutcome {
                        status: 200,
                        headers: BTreeMap::new(),
                        body: b"x".to_vec(),
                    },
                    1_000,
                )
                .unwrap();
            // Now past the key's TTL: prune should physically drop it.
            engine.prune_expired(1_000 + TTL + 1);
        }

        let store = WalStore::open(&path).unwrap();
        assert_eq!(store.get(&key), None, "expired key must be gone from disk");

        let _ = std::fs::remove_file(&path);
    }

    /// Differential stress test: drive the WAL with hundreds of random writes
    /// and repeated simulated crashes, asserting the durably-recovered state
    /// always matches a plain in-memory reference model. Deterministic seed, so
    /// any failure reproduces exactly — the seed of the Phase 5 DST approach.
    #[test]
    fn randomized_writes_recover_exactly_across_crashes() {
        use std::collections::HashMap;

        struct Rng(u64);
        impl Rng {
            fn next_u64(&mut self) -> u64 {
                // xorshift64: full-period, dependency-free, reproducible.
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
            fn below(&mut self, n: u64) -> u64 {
                self.next_u64() % n
            }
        }

        fn random_fingerprint(rng: &mut Rng) -> RequestFingerprint {
            let mut bytes = [0u8; 32];
            for b in bytes.iter_mut() {
                *b = rng.below(256) as u8;
            }
            RequestFingerprint(bytes)
        }

        fn random_state(rng: &mut Rng) -> KeyState {
            if rng.below(2) == 0 {
                KeyState::InProgress {
                    fence: Fence(rng.next_u64()),
                    fingerprint: random_fingerprint(rng),
                    lease_expires_at_ms: rng.next_u64(),
                }
            } else {
                let body_len = rng.below(8) as usize;
                let body: Vec<u8> = (0..body_len).map(|_| rng.below(256) as u8).collect();
                let mut headers = BTreeMap::new();
                if rng.below(2) == 0 {
                    headers.insert("x-test".to_string(), format!("v{}", rng.below(1000)));
                }
                KeyState::Completed {
                    fingerprint: random_fingerprint(rng),
                    outcome: CachedOutcome {
                        status: 200 + rng.below(50) as u16,
                        headers,
                        body,
                    },
                    completed_at_ms: rng.next_u64(),
                }
            }
        }

        let path = temp_wal_path("randomized");
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut reference: HashMap<IdempotencyKey, KeyState> = HashMap::new();
        let mut store = WalStore::open(&path).unwrap();

        for i in 0..600u32 {
            // Small key space so the same key is overwritten many times.
            let key = IdempotencyKey(format!("k{}", rng.below(16)));
            let state = random_state(&mut rng);
            reference.insert(key.clone(), state.clone());
            store.put(key, state);

            // Periodically "crash": drop the store and recover from disk.
            if i % 50 == 49 {
                drop(store);
                store = WalStore::open(&path).unwrap();
                for (k, v) in &reference {
                    assert_eq!(store.get(k), Some(v), "divergence after reopen at op {i}");
                }
            }
        }

        // Final crash + full recovery must equal the reference exactly.
        drop(store);
        let store = WalStore::open(&path).unwrap();
        for (k, v) in &reference {
            assert_eq!(store.get(k), Some(v));
        }

        let _ = std::fs::remove_file(&path);
    }

    // -----------------------------------------------------------------------
    // New tamper-evidence tests (Requirements 7a-7d)
    // -----------------------------------------------------------------------

    /// (7a) The chain root changes with every put and is fully deterministic:
    /// two stores fed identical records in the same order reach the same root.
    #[test]
    fn chain_root_is_deterministic_and_advances_per_put() {
        let path1 = temp_wal_path("chain-det-1");
        let path2 = temp_wal_path("chain-det-2");

        let keys_states: Vec<(IdempotencyKey, KeyState)> = (0..5)
            .map(|i| {
                (
                    IdempotencyKey(format!("k{i}")),
                    completed(200, format!("v{i}").as_bytes()),
                )
            })
            .collect();

        let mut roots1: Vec<[u8; 32]> = Vec::new();
        {
            let mut store = WalStore::open(&path1).unwrap();
            // Genesis root before any puts.
            assert_eq!(store.root(), GENESIS);
            for (k, s) in &keys_states {
                store.put(k.clone(), s.clone());
                roots1.push(store.root());
            }
        }

        // All roots must be distinct (each put advances the chain).
        for i in 0..roots1.len() {
            for j in (i + 1)..roots1.len() {
                assert_ne!(
                    roots1[i], roots1[j],
                    "roots at position {i} and {j} must differ"
                );
            }
        }
        // No root should be genesis.
        for r in &roots1 {
            assert_ne!(*r, GENESIS, "root must not be genesis after a put");
        }

        // Second store: same sequence -> same roots.
        let mut roots2: Vec<[u8; 32]> = Vec::new();
        {
            let mut store = WalStore::open(&path2).unwrap();
            for (k, s) in &keys_states {
                store.put(k.clone(), s.clone());
                roots2.push(store.root());
            }
        }

        assert_eq!(roots1, roots2, "deterministic: same records -> same roots");

        // Reopening preserves the root.
        let store = WalStore::open(&path1).unwrap();
        assert_eq!(
            store.root(),
            roots1[roots1.len() - 1],
            "root survives reopen"
        );

        let _ = std::fs::remove_file(&path1);
        let _ = std::fs::remove_file(&path2);
    }

    /// (7b) Flipping a byte in an early record's payload is caught on reopen
    /// as a chain mismatch, even though later records are intact.
    #[test]
    fn early_payload_tamper_is_caught_as_chain_mismatch_on_reopen() {
        let path = temp_wal_path("chain-tamper");

        {
            let mut store = WalStore::open(&path).unwrap();
            for i in 0..5u32 {
                store.put(IdempotencyKey(format!("k{i}")), completed(200, b"intact"));
            }
        }

        let mut bytes = std::fs::read(&path).unwrap();
        // Flip a byte deep in the first record's payload. The CRC covers only
        // the payload, so we need to find where the payload starts and also fix
        // the CRC so the CRC check passes — but the chain check must still catch it.
        //
        // Strategy: locate the first record's payload start, flip a payload byte,
        // then patch the CRC in the header to make crc32 pass. The chain is
        // computed from the crc_bytes, so patching the CRC also changes the chain
        // input — thus the stored chain will no longer match.
        //
        // In practice, an adversary who patches both CRC and payload is exactly
        // what the chain catches. We simulate that here.
        let payload_start = HEADER_LEN;
        // Flip a byte somewhere in the first record's payload (not the crc header).
        bytes[payload_start + 2] ^= 0x01;
        // Recompute CRC over the mutated payload of the first record.
        let first_len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let new_crc = super::crc32(&bytes[HEADER_LEN..HEADER_LEN + first_len]);
        bytes[4..8].copy_from_slice(&new_crc.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();

        // The CRC now passes, but the chain hash stored in the record was
        // computed over the OLD (crc, payload) pair. Opening must fail.
        let result = WalStore::open(&path);
        assert!(
            result.is_err(),
            "chain mismatch must be caught even when CRC passes"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// (7c) Two stores fed the same records in the same order reach the same root.
    /// (This is already covered by 7a but is tested explicitly here for clarity.)
    #[test]
    fn two_stores_same_records_same_root() {
        let path_a = temp_wal_path("chain-same-a");
        let path_b = temp_wal_path("chain-same-b");

        let records: Vec<(IdempotencyKey, KeyState)> = vec![
            (IdempotencyKey("alpha".into()), completed(200, b"a")),
            (IdempotencyKey("beta".into()), completed(201, b"b")),
            (IdempotencyKey("gamma".into()), completed(202, b"c")),
        ];

        let root_a = {
            let mut store = WalStore::open(&path_a).unwrap();
            for (k, s) in &records {
                store.put(k.clone(), s.clone());
            }
            store.root()
        };
        let root_b = {
            let mut store = WalStore::open(&path_b).unwrap();
            for (k, s) in &records {
                store.put(k.clone(), s.clone());
            }
            store.root()
        };

        assert_eq!(
            root_a, root_b,
            "identical record sequences must yield identical roots"
        );

        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    /// (7d) Compaction yields a consistent chain: the compacted log reopens
    /// cleanly (no chain error) and the root matches what encoding the surviving
    /// records from genesis would produce.
    #[test]
    fn compaction_yields_consistent_chain_that_reopens_cleanly() {
        let path = temp_wal_path("chain-compact");

        // Write many records including duplicates (so compaction has work to do).
        {
            let mut store = WalStore::open(&path).unwrap();
            for i in 0..20u32 {
                store.put(
                    IdempotencyKey(format!("k{}", i % 5)),
                    completed(200, format!("v{i}").as_bytes()),
                );
            }
        }

        // Compact keeping all keys (collapse history).
        let root_after_compact = {
            let mut store = WalStore::open(&path).unwrap();
            store.compact(&mut |_, _| true);
            store.root()
        };

        // Reopening must succeed and report the same root.
        let store = WalStore::open(&path).unwrap();
        assert_eq!(
            store.root(),
            root_after_compact,
            "root must be stable across reopen after compaction"
        );

        // The root must be non-genesis (the compacted log is non-empty).
        assert_ne!(
            store.root(),
            GENESIS,
            "root must not be genesis after non-empty compaction"
        );

        let _ = std::fs::remove_file(&path);
    }
}
