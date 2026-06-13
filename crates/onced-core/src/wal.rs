//! Write-ahead log: crash-safe durability for the idempotency store.
//!
//! Every state change is appended to a log file and forced to disk (`fsync`)
//! *before* it is acknowledged; on restart the log is replayed to rebuild the
//! in-memory index exactly. This is the classic database durability discipline
//! (Gray, "The Transaction Concept"). Each record is length-framed and
//! CRC32-checksummed so a torn or corrupt tail (the signature of a crash
//! mid-append) is detected and discarded rather than trusted.
//!
//! Records are written with no external dependencies: a small hand-rolled
//! binary format, so the on-disk layout is fully auditable.
//!
//! Production code is written test-first; the tests below are watched failing
//! before `WalStore`, `encode_record`, and `decode_record` exist.

use crate::store::Store;
use crate::{CachedOutcome, Fence, IdempotencyKey, KeyState, RequestFingerprint};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const TAG_IN_PROGRESS: u8 = 0;
const TAG_COMPLETED: u8 = 1;

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
/// CRC-checksummed record: `[payload_len: u32][crc32: u32][payload]`.
pub(crate) fn encode_record(key: &IdempotencyKey, state: &KeyState) -> Vec<u8> {
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
        } => {
            payload.push(TAG_COMPLETED);
            payload.extend_from_slice(&fingerprint.0);
            put_u16(&mut payload, outcome.status);
            put_u32(&mut payload, outcome.headers.len() as u32);
            for (name, value) in &outcome.headers {
                put_str(&mut payload, name);
                put_str(&mut payload, value);
            }
            put_bytes(&mut payload, &outcome.body);
        }
    }

    let mut framed = Vec::with_capacity(8 + payload.len());
    put_u32(&mut framed, payload.len() as u32);
    put_u32(&mut framed, crc32(&payload));
    framed.extend_from_slice(&payload);
    framed
}

/// Decode one record from the front of `buf`. Returns the number of bytes
/// consumed plus the record, or `None` if `buf` does not begin with a complete,
/// checksum-valid record (truncated tail or corruption).
pub(crate) fn decode_record(buf: &[u8]) -> Option<(usize, IdempotencyKey, KeyState)> {
    let header = buf.get(0..8)?;
    let len = u32::from_le_bytes(header[0..4].try_into().ok()?) as usize;
    let crc = u32::from_le_bytes(header[4..8].try_into().ok()?);
    let total = 8usize.checked_add(len)?;
    let payload = buf.get(8..total)?;
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
            }
        }
        _ => return None,
    };
    Some((total, key, state))
}

/// A durable [`Store`]: an in-memory index kept in lock-step with an append-only
/// write-ahead log on disk. Reads hit memory; every write is appended and
/// `fsync`ed before it is acknowledged. On `open` the log is replayed and any
/// torn or corrupt tail is truncated away.
pub struct WalStore {
    index: HashMap<IdempotencyKey, KeyState>,
    file: std::fs::File,
}

impl WalStore {
    /// Open (creating if absent) the log at `path`, replaying it into memory.
    pub fn open(path: &Path) -> std::io::Result<Self> {
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
        while let Some((consumed, key, state)) = decode_record(&buf[offset..]) {
            index.insert(key, state);
            offset += consumed;
        }

        // Drop any torn/corrupt tail past the last valid record and position the
        // write cursor at the end of durable data, so future appends are clean.
        file.set_len(offset as u64)?;
        file.seek(SeekFrom::Start(offset as u64))?;

        Ok(Self { index, file })
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
        let framed = encode_record(&key, &state);
        // Fail-stop durability: if we cannot append and fsync, we must not
        // pretend the state change happened. Halting is safer than acknowledging
        // a non-durable write (standard WAL policy; graceful handling is a
        // later refinement, see the design doc).
        self.file
            .write_all(&framed)
            .expect("onced WAL: append failed; refusing to continue");
        self.file
            .sync_all()
            .expect("onced WAL: fsync failed; refusing to continue");
        self.index.insert(key, state);
    }
}

#[cfg(test)]
mod tests {
    use crate::store::Store;
    use crate::wal::{decode_record, encode_record, WalStore};
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
        let framed = encode_record(&key, &in_progress);
        let (consumed, k, s) = decode_record(&framed).expect("valid record decodes");
        assert_eq!(consumed, framed.len());
        assert_eq!(k, key);
        assert_eq!(s, in_progress);

        let done = completed(201, b"charged");
        let framed = encode_record(&key, &done);
        let (consumed, k, s) = decode_record(&framed).expect("valid record decodes");
        assert_eq!(consumed, framed.len());
        assert_eq!(k, key);
        assert_eq!(s, done);
    }

    /// A truncated/garbage tail (a crash mid-append) decodes to None, never a
    /// bogus record.
    #[test]
    fn a_truncated_record_decodes_to_none() {
        let key = IdempotencyKey("k".into());
        let framed = encode_record(&key, &completed(200, b"ok"));
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
            )
            .unwrap();

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
}
