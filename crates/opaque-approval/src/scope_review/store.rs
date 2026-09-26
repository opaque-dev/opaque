use super::*;
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    fs::{File, OpenOptions},
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    sync::Mutex,
};

const SCHEMA: &str = "CREATE TABLE binding(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL,last_now INTEGER NOT NULL);
    CREATE TABLE rounds(id TEXT PRIMARY KEY,review TEXT NOT NULL,expires INTEGER NOT NULL,state TEXT NOT NULL,receipt TEXT);
    CREATE INDEX pending_expiry ON rounds(state,expires);
    PRAGMA user_version=1;";

pub(super) struct Ledger {
    connection: Mutex<Connection>,
    _lock: WriterLock,
}
struct WriterLock(File);
impl Drop for WriterLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn db<T>(value: rusqlite::Result<T>) -> Result<T> {
    value.map_err(|_| Error::Storage)
}
fn json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| Error::Storage)
}
fn parse<T: for<'a> Deserialize<'a>>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|_| Error::Storage)
}
fn state(value: &str) -> Result<RoundState> {
    match value {
        "pending" => Ok(RoundState::Pending),
        "accepted" => Ok(RoundState::Accepted),
        "rejected" => Ok(RoundState::Rejected),
        "cancelled" => Ok(RoundState::Cancelled),
        "cancelled_restart" => Ok(RoundState::CancelledRestart),
        "expired" => Ok(RoundState::Expired),
        _ => Err(Error::Storage),
    }
}
fn validate_file(file: &File) -> Result<()> {
    let m = file.metadata().map_err(|_| Error::Storage)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.mode() & 0o077 != 0
        || m.uid() != unsafe { libc::geteuid() }
    {
        return Err(Error::Storage);
    }
    Ok(())
}
fn private_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Storage)?;
    validate_file(&file)?;
    Ok(file)
}
type SchemaRow = (String, String, String, Option<String>);
fn schema(conn: &Connection) -> Result<Vec<SchemaRow>> {
    let mut stmt =
        db(conn.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"))?;
    db(stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| Error::Storage)
}
fn tick(conn: &Connection, now: i64) -> Result<()> {
    let last: i64 =
        db(conn.query_row("SELECT last_now FROM binding WHERE id=1", [], |r| r.get(0)))?;
    if now < 0 || now < last {
        return Err(Error::ClockRegression);
    }
    db(conn.execute("UPDATE binding SET last_now=?1 WHERE id=1", [now]))?;
    db(conn.execute(
        "UPDATE rounds SET state='expired' WHERE state='pending' AND expires<=?1",
        [now],
    ))?;
    Ok(())
}
fn load(conn: &Connection, id: &str) -> Result<RoundSnapshot> {
    if uuid::Uuid::parse_str(id).is_err() {
        return Err(Error::NotFound);
    }
    let row: Option<(String, String, Option<String>)> = db(conn
        .query_row(
            "SELECT state,review,receipt FROM rounds WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional())?;
    let (status, review, receipt) = row.ok_or(Error::NotFound)?;
    Ok(RoundSnapshot {
        state: state(&status)?,
        review: parse(&review)?,
        receipt: receipt.as_deref().map(parse).transpose()?,
    })
}

impl Ledger {
    pub(super) fn retained(&self, id: &str) -> Result<RoundSnapshot> {
        let conn = self.connection.lock().map_err(|_| Error::Storage)?;
        load(&conn, id)
    }
    pub(super) fn list_retained(&self, limit: u32) -> Result<(u64, Vec<RoundSnapshot>)> {
        if !(1..=100).contains(&limit) {
            return Err(Error::Invalid);
        }
        let conn = self.connection.lock().map_err(|_| Error::Storage)?;
        let total: u64 = db(conn.query_row("SELECT COUNT(*) FROM rounds", [], |r| r.get(0)))?;
        let mut stmt=db(conn.prepare("SELECT id FROM rounds ORDER BY json_extract(review,'$.document.created_at') DESC,id ASC LIMIT ?1"))?;
        let ids = db(stmt.query_map([limit], |r| r.get::<_, String>(0)))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| Error::Storage)?;
        let reviews = ids
            .iter()
            .map(|id| load(&conn, id))
            .collect::<Result<Vec<_>>>()?;
        Ok((total, reviews))
    }
    pub(super) fn open(
        path: &Path,
        owner: &AuthorityOwner,
        broker_key: &str,
        now: i64,
    ) -> Result<Self> {
        if !path.is_absolute() || now < 0 {
            return Err(Error::Storage);
        }
        let parent = path.parent().ok_or(Error::Storage)?;
        let m = std::fs::symlink_metadata(parent).map_err(|_| Error::Storage)?;
        if !m.is_dir() || m.mode() & 0o077 != 0 || m.uid() != unsafe { libc::geteuid() } {
            return Err(Error::Storage);
        }
        let file = private_file(path)?;
        if file.metadata().map_err(|_| Error::Storage)?.len() > 256 * 1024 * 1024 {
            return Err(Error::Capacity);
        }
        let canonical = path.canonicalize().map_err(|_| Error::Storage)?;
        let mut lock_path = canonical.as_os_str().to_os_string();
        lock_path.push(".writer.lock");
        let lock = WriterLock(private_file(Path::new(&lock_path))?);
        if unsafe { libc::flock(lock.0.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::Storage);
        }
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut sidecar = canonical.as_os_str().to_os_string();
            sidecar.push(suffix);
            let sidecar = Path::new(&sidecar);
            match std::fs::symlink_metadata(sidecar) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error::Storage),
                Ok(_) => {
                    let file = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                        .open(sidecar)
                        .map_err(|_| Error::Storage)?;
                    validate_file(&file)?;
                }
            }
        }
        let mut conn = db(Connection::open(&canonical))?;
        let original = file.metadata().map_err(|_| Error::Storage)?;
        let opened = std::fs::metadata(&canonical).map_err(|_| Error::Storage)?;
        if original.ino() != opened.ino() || original.dev() != opened.dev() {
            return Err(Error::Storage);
        }
        db(conn.busy_timeout(std::time::Duration::from_secs(2)))?;
        db(conn.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;"))?;
        let integrity: String = db(conn.query_row("PRAGMA quick_check", [], |r| r.get(0)))?;
        if integrity != "ok" {
            return Err(Error::Storage);
        }
        let version: i64 = db(conn.query_row("PRAGMA user_version", [], |r| r.get(0)))?;
        let tx = db(conn.transaction())?;
        let binding = json(&("opaque.scope.review-ledger.v1", owner, broker_key))?;
        if version == 0 {
            if !schema(&tx)?.is_empty() {
                return Err(Error::Storage);
            }
            db(tx.execute_batch(SCHEMA))?;
            db(tx.execute("INSERT INTO binding VALUES(1,?1,?2)", params![binding, now]))?;
        } else if version != 1 {
            return Err(Error::Storage);
        }
        let expected = db(Connection::open_in_memory())?;
        db(expected.execute_batch(SCHEMA))?;
        if schema(&tx)? != schema(&expected)? {
            return Err(Error::Storage);
        }
        let (stored, last): (String, i64) = db(tx.query_row(
            "SELECT value,last_now FROM binding WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        if stored != binding || last < 0 {
            return Err(Error::Storage);
        }
        validate_rows(&tx, owner, broker_key, last)?;
        tick(&tx, now)?;
        // A running native ceremony cannot be recovered from a historical ledger.
        db(tx.execute(
            "UPDATE rounds SET state='cancelled_restart' WHERE state='pending'",
            [],
        ))?;
        db(tx.commit())?;
        Ok(Self {
            connection: Mutex::new(conn),
            _lock: lock,
        })
    }

    fn transaction<T>(&self, now: i64, work: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let mut conn = self.connection.lock().map_err(|_| Error::Storage)?;
        let mut tx = db(conn.transaction())?;
        tick(&tx, now)?;
        let mut save = db(tx.savepoint())?;
        let result = work(&save);
        if result.is_ok() {
            db(save.commit())?;
        } else {
            db(save.rollback())?;
            drop(save);
        }
        db(tx.commit())?;
        result
    }

    pub(super) fn insert(&self, review: &SignedReview, now: i64) -> Result<()> {
        self.transaction(now, |conn| {
            let (total, pending): (i64, i64) = db(conn.query_row(
                "SELECT COUNT(*),COALESCE(SUM(state='pending'),0) FROM rounds",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ))?;
            let pages: u64 = db(conn.query_row("PRAGMA page_count", [], |r| r.get(0)))?;
            let size: u64 = db(conn.query_row("PRAGMA page_size", [], |r| r.get(0)))?;
            // Keep capacity for all 64 pending decisions, each up to 256 KiB,
            // plus SQLite page overhead. Accepting a decision must not push an
            // otherwise valid ledger beyond its 256 MiB reopen ceiling.
            if total >= 10_000 || pending >= 64 || pages.saturating_mul(size) > 238 * 1024 * 1024 {
                return Err(Error::Capacity);
            }
            db(conn.execute(
                "INSERT INTO rounds VALUES(?1,?2,?3,'pending',NULL)",
                params![
                    review.document.round_id,
                    json(review)?,
                    review.document.expires_at
                ],
            ))?;
            Ok(())
        })
    }

    pub(super) fn decide(
        &self,
        id: &str,
        now: i64,
        verify: impl FnOnce(&RoundSnapshot) -> Result<DecisionReceipt>,
    ) -> Result<DecisionReceipt> {
        self.transaction(now, |conn| {
            let snapshot = load(conn, id)?;
            if snapshot.state == RoundState::Expired {
                return Err(Error::Expired);
            }
            if snapshot.state != RoundState::Pending {
                return Err(Error::Closed);
            }
            let receipt = verify(&snapshot)?;
            let state = if receipt.response.decision == Decision::Approve {
                "accepted"
            } else {
                "rejected"
            };
            db(conn.execute(
                "UPDATE rounds SET state=?1,receipt=?2 WHERE id=?3 AND state='pending'",
                params![state, json(&receipt)?, id],
            ))?;
            Ok(receipt)
        })
    }

    pub(super) fn read(
        &self,
        id: &str,
        now: i64,
        verify: impl FnOnce(&RoundSnapshot) -> Result<()>,
    ) -> Result<RoundSnapshot> {
        self.transaction(now, |conn| {
            let snapshot = load(conn, id)?;
            verify(&snapshot)?;
            Ok(snapshot)
        })
    }

    pub(super) fn cancel(
        &self,
        id: &str,
        now: i64,
        verify: impl FnOnce(&RoundSnapshot) -> Result<()>,
    ) -> Result<()> {
        self.transaction(now, |conn| {
            let snapshot = load(conn, id)?;
            verify(&snapshot)?;
            if !matches!(snapshot.state, RoundState::Pending | RoundState::Accepted) {
                return Err(Error::Closed);
            }
            db(conn.execute("UPDATE rounds SET state='cancelled' WHERE id=?1", [id]))?;
            Ok(())
        })
    }
}

fn validate_rows(
    conn: &Connection,
    owner: &AuthorityOwner,
    broker_key: &str,
    last: i64,
) -> Result<()> {
    let mut stmt = db(conn.prepare("SELECT id,review,expires,state,receipt FROM rounds"))?;
    let mut rows = db(stmt.query([]))?;
    let mut count = 0;
    while let Some(row) = db(rows.next())? {
        count += 1;
        if count > 10_000 {
            return Err(Error::Capacity);
        }
        let id: String = db(row.get(0))?;
        let review: SignedReview = parse(&db(row.get::<_, String>(1))?)?;
        let expires: i64 = db(row.get(2))?;
        let state = state(&db(row.get::<_, String>(3))?)?;
        let receipt: Option<DecisionReceipt> = db(row.get::<_, Option<String>>(4))?
            .as_deref()
            .map(parse)
            .transpose()?;
        review
            .verify(broker_key, review.document.created_at)
            .map_err(|_| Error::Storage)?;
        if id != review.document.round_id
            || expires != review.document.expires_at
            || &review.document.authority.owner != owner
            || review.document.created_at > last
        {
            return Err(Error::Storage);
        }
        if let Some(receipt) = receipt {
            receipt.verify(broker_key).map_err(|_| Error::Storage)?;
            if receipt.review != review
                || receipt.accepted_at > last
                || !matches!(
                    state,
                    RoundState::Accepted | RoundState::Rejected | RoundState::Cancelled
                )
                || (state == RoundState::Accepted && receipt.response.decision != Decision::Approve)
                || (state == RoundState::Rejected && receipt.response.decision != Decision::Reject)
            {
                return Err(Error::Storage);
            }
        } else if matches!(state, RoundState::Accepted | RoundState::Rejected) {
            return Err(Error::Storage);
        }
    }
    Ok(())
}
