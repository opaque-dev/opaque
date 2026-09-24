//! Single-owner scope authority ledger for a trusted host, not a runtime route.
//!
//! The host authenticates callers, verifies signed issuance/review/evaluator
//! receipts, prepares the effective provider operation, prevents bypass, and
//! orders current policy/identity changes with [`AuthorityGuard`]. Callbacks must
//! be bounded, local, non-reentrant and must not call the network. This module
//! supplies transactional accounting and one-time dispatch claims; it does not
//! make a permissive callback safe. No existing task or MCP approval is relaxed.
//!
//! Custody protects this structurally validated SQLite ledger. It is not a
//! cryptographic anti-rollback store: recovery from an older valid snapshot needs
//! independently retained high-water state and old-writer fencing by the host.
//! No lease, rate-limit or automatic owner failover is implemented. Portable
//! exports describe retained state only. Restart preserves charges and turns
//! unfinished attempts UNKNOWN.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use opaque_core::scope::{
    AdmissionEvidence, AuthorityOwner, MAX_DEPTH, PreparedAction, ScopeError, ScopeGrant,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

/// Implement only in trusted application code backed by verified authority.
///
/// `verify_action` receives the leaf grant, not an authenticated ancestry. The
/// host must retain independently verified issuance/delegation context for all
/// applicable ancestors and check current issuer/requester/reviewer eligibility.
/// The ledger checks structural narrowing and ancestor revocation, not IdP claims.
/// Do not read this same store from a callback: its writer lock is already held.
///
/// When external authority can change concurrently, the host must hold its
/// authority-ordering gate across the entire reserve/claim call, and acquire the
/// same gate for policy/identity invalidation. A callback-only check whose guard
/// is released before the ledger commits does not order external revocation.
pub trait AuthorityGuard {
    fn verify_scope(&self, grant: &ScopeGrant, now: i64) -> Result<(), String>;
    fn verify_action(
        &self,
        grant: &ScopeGrant,
        action: &PreparedAction,
        evidence: &AdmissionEvidence,
        now: i64,
    ) -> Result<(), String>;
}

#[derive(Debug, Error)]
pub enum ScopeStoreError {
    #[error("scope ledger I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("scope ledger database failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("scope ledger serialization failed")]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Validation(#[from] ScopeError),
    #[error("scope ledger custody or structural integrity check failed")]
    Corrupt,
    #[error("scope ledger already has a writer")]
    Locked,
    #[error("scope ledger mutex is poisoned")]
    Poisoned,
    #[error("scope or action not found")]
    NotFound,
    #[error("wrong tenant, broker, or authority generation")]
    OwnerMismatch,
    #[error("scope is revoked, expired, or not yet active")]
    Inactive,
    #[error("clock precedes the last observed ledger time")]
    ClockRollback,
    #[error("request identity already binds different content")]
    IdempotencyConflict,
    #[error("an ancestor budget is exhausted")]
    BudgetExceeded,
    #[error("attempt or dispatch claim is already consumed")]
    Consumed,
    #[error("invalid state transition")]
    InvalidTransition,
    #[error("host authority verification failed: {0}")]
    Authority(String),
}

// Public, storage-independent evidence contracts. Preserve existing imports.
use opaque_core::scope_evidence::ScopeEvidence;
pub use opaque_core::scope_evidence::{
    ActionRecord, AuthorityEvent, EventKind, ExecutionState, ScopeRecord,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    ApiAccepted,
    Rejected,
    Unknown,
}

const META: &str = "CREATE TABLE scope_meta (id INTEGER PRIMARY KEY CHECK(id = 1), owner TEXT NOT NULL, last_seen INTEGER NOT NULL CHECK(last_seen >= 0))";
const SCOPES: &str =
    "CREATE TABLE scope_grants (id TEXT PRIMARY KEY NOT NULL, record TEXT NOT NULL)";
const ACTIONS: &str = "CREATE TABLE scope_actions (id TEXT PRIMARY KEY NOT NULL, scope_id TEXT NOT NULL REFERENCES scope_grants(id), subject TEXT NOT NULL, request_id TEXT NOT NULL, record TEXT NOT NULL, UNIQUE(scope_id, subject, request_id))";
const EVENTS: &str =
    "CREATE TABLE scope_events (sequence INTEGER PRIMARY KEY, record TEXT NOT NULL)";

struct WriterLock(File);
impl Drop for WriterLock {
    fn drop(&mut self) {
        // SAFETY: this File owns its descriptor until after Drop returns.
        if unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) } != 0 {
            tracing::error!("scope writer unlock failed");
        }
    }
}

pub struct ScopeStore {
    owner: AuthorityOwner,
    connection: Option<Mutex<Connection>>,
    _writer_lock: WriterLock,
}

impl Drop for ScopeStore {
    fn drop(&mut self) {
        drop(self.connection.take());
    }
}

impl ScopeStore {
    /// Requires an owner-only custody directory. A different owner/generation
    /// cannot open an existing ledger; migration is deliberately unsupported.
    pub fn open(path: &Path, owner: AuthorityOwner) -> Result<Self, ScopeStoreError> {
        owner.validate()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        let parent_metadata = parent.metadata()?;
        // SAFETY: geteuid takes no arguments and has no memory preconditions.
        let uid = unsafe { libc::geteuid() };
        if !parent_metadata.is_dir()
            || parent_metadata.uid() != uid
            || parent_metadata.mode() & 0o077 != 0
        {
            return Err(ScopeStoreError::Corrupt);
        }
        let file = custody_file(path)?;
        let canonical = path.canonicalize()?;
        let mut lock_path = canonical.as_os_str().to_os_string();
        lock_path.push(".writer.lock");
        let lock = custody_file(Path::new(&lock_path))?;
        // SAFETY: lock owns this descriptor and remains alive with the store.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let err = std::io::Error::last_os_error();
            return if err.kind() == std::io::ErrorKind::WouldBlock {
                Err(ScopeStoreError::Locked)
            } else {
                Err(err.into())
            };
        }
        let writer_lock = WriterLock(lock);
        for suffix in ["-journal", "-wal", "-shm"] {
            let sibling = format!("{}{suffix}", canonical.display());
            if Path::new(&sibling).symlink_metadata().is_ok() {
                drop(custody_file(Path::new(&sibling))?);
            }
        }
        drop(file);
        let mut connection = Connection::open(&canonical)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA journal_mode = DELETE; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")?;
        let integrity: String = connection.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if integrity != "ok" {
            return Err(ScopeStoreError::Corrupt);
        }
        let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let objects: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )?;
        if version == 0 && objects == 0 {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            for sql in [META, SCOPES, ACTIONS, EVENTS] {
                tx.execute_batch(sql)?;
            }
            tx.execute(
                "INSERT INTO scope_meta VALUES (1, ?1, 0)",
                [serde_json::to_string(&owner)?],
            )?;
            tx.execute_batch("PRAGMA user_version = 1")?;
            tx.commit()?;
        } else if version != 1 {
            return Err(ScopeStoreError::Corrupt);
        }
        verify_schema(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (stored_owner, last_seen) = metadata(&tx)?;
        if owner != stored_owner {
            return Err(ScopeStoreError::OwnerMismatch);
        }
        verify_all(&tx, &owner, last_seen)?;
        let actions = all_actions(&tx)?;
        for mut action in actions {
            if matches!(
                action.state,
                ExecutionState::Reserved | ExecutionState::DispatchClaimed
            ) {
                action.state = ExecutionState::Unknown;
                save_action(&tx, &action)?;
                append_event(
                    &tx,
                    &action.action.scope_id,
                    Some(&action.action.action_id),
                    EventKind::Interrupted,
                    None,
                    &action.digest,
                )?;
            }
        }
        tx.commit()?;
        Ok(Self {
            owner,
            connection: Some(Mutex::new(connection)),
            _writer_lock: writer_lock,
        })
    }

    pub fn issue_scope(
        &self,
        grant: ScopeGrant,
        guard: &impl AuthorityGuard,
        now: i64,
    ) -> Result<ScopeRecord, ScopeStoreError> {
        let grant = grant.canonicalized()?;
        if grant.owner != self.owner {
            return Err(ScopeStoreError::OwnerMismatch);
        }
        self.mutate(now, |tx| {
            if let Some(existing) = maybe_scope(tx, &grant.scope_id)? {
                return if existing.grant == grant {
                    Ok(existing)
                } else {
                    Err(ScopeStoreError::IdempotencyConflict)
                };
            }
            if now >= grant.expires_at {
                return Err(ScopeStoreError::Inactive);
            }
            if let Some(parent_id) = &grant.parent_id {
                let ancestors = active_chain(tx, parent_id, now)?;
                grant.validate_child_of(&ancestors[0].grant)?;
                if ancestors.len() > MAX_DEPTH as usize {
                    return Err(ScopeStoreError::Validation(ScopeError::NotSubset));
                }
            }
            guard
                .verify_scope(&grant, now)
                .map_err(ScopeStoreError::Authority)?;
            let record = ScopeRecord {
                digest: grant.digest()?,
                grant,
                issued_at: now,
                revoked_at: None,
                charged_attempts: 0,
                charged_resources: BTreeSet::new(),
            };
            tx.execute(
                "INSERT INTO scope_grants VALUES (?1, ?2)",
                params![record.grant.scope_id, serde_json::to_string(&record)?],
            )?;
            append_event(
                tx,
                &record.grant.scope_id,
                None,
                EventKind::ScopeIssued,
                Some(now),
                &record.digest,
            )?;
            Ok(record)
        })
    }

    /// Commits one permanent charge across the entire ancestry, or none.
    /// Exact duplicate proposals return their existing record, never a new grant.
    pub fn reserve(
        &self,
        action: PreparedAction,
        evidence: AdmissionEvidence,
        guard: &impl AuthorityGuard,
        now: i64,
    ) -> Result<ActionRecord, ScopeStoreError> {
        let action = action.canonicalized()?;
        if action.owner != self.owner {
            return Err(ScopeStoreError::OwnerMismatch);
        }
        self.mutate(now, |tx| {
            let existing: Option<String> = tx.query_row("SELECT record FROM scope_actions WHERE id = ?1 OR (scope_id = ?2 AND subject = ?3 AND request_id = ?4)", params![action.action_id, action.scope_id, action.subject, action.request_id], |r| r.get(0)).optional()?;
            if let Some(json) = existing {
                let record: ActionRecord = serde_json::from_str(&json)?;
                return if record.action == action { Ok(record) } else { Err(ScopeStoreError::IdempotencyConflict) };
            }
            let mut chain = active_chain(tx, &action.scope_id, now)?;
            evidence.validate_for(&chain[0].grant, &action, now)?;
            guard.verify_action(&chain[0].grant, &action, &evidence, now).map_err(ScopeStoreError::Authority)?;
            for scope in &chain {
                if scope.charged_attempts >= scope.grant.max_charged_attempts
                    || (!scope.charged_resources.contains(&action.resource) && scope.charged_resources.len() >= scope.grant.max_distinct_resources as usize)
                { return Err(ScopeStoreError::BudgetExceeded); }
            }
            for scope in &mut chain {
                scope.charged_attempts += 1;
                scope.charged_resources.insert(action.resource.clone());
                save_scope(tx, scope)?;
            }
            let record = ActionRecord { digest: action.digest()?, action, evidence, reserved_at: now, dispatch_claimed_at: None, finished_at: None, state: ExecutionState::Reserved };
            tx.execute("INSERT INTO scope_actions VALUES (?1, ?2, ?3, ?4, ?5)", params![record.action.action_id, record.action.scope_id, record.action.subject, record.action.request_id, serde_json::to_string(&record)?])?;
            append_event(tx, &record.action.scope_id, Some(&record.action.action_id), EventKind::AttemptCharged, Some(now), &record.digest)?;
            Ok(record)
        })
    }

    /// The single irreversible final dispatch claim. If its acknowledgment is
    /// lost, lookup/reconcile; never retry a provider send based on a duplicate.
    pub fn claim_dispatch(
        &self,
        action_id: &str,
        expected_digest: &str,
        guard: &impl AuthorityGuard,
        now: i64,
    ) -> Result<ActionRecord, ScopeStoreError> {
        self.mutate(now, |tx| {
            let mut record = load_action(tx, action_id)?;
            if record.digest != expected_digest {
                return Err(ScopeStoreError::IdempotencyConflict);
            }
            if record.state != ExecutionState::Reserved {
                return Err(ScopeStoreError::Consumed);
            }
            let chain = active_chain(tx, &record.action.scope_id, now)?;
            record
                .evidence
                .validate_for(&chain[0].grant, &record.action, now)?;
            guard
                .verify_action(&chain[0].grant, &record.action, &record.evidence, now)
                .map_err(ScopeStoreError::Authority)?;
            record.state = ExecutionState::DispatchClaimed;
            record.dispatch_claimed_at = Some(now);
            save_action(tx, &record)?;
            append_event(
                tx,
                &record.action.scope_id,
                Some(action_id),
                EventKind::DispatchClaimed,
                Some(now),
                &record.digest,
            )?;
            Ok(record)
        })
    }

    /// Records observation only. No outcome refunds an attempt or permits replay.
    pub fn finish(
        &self,
        action_id: &str,
        outcome: Outcome,
        now: i64,
    ) -> Result<ActionRecord, ScopeStoreError> {
        self.mutate(now, |tx| {
            let mut record = load_action(tx, action_id)?;
            if !matches!(
                record.state,
                ExecutionState::Reserved | ExecutionState::DispatchClaimed
            ) || (outcome == Outcome::ApiAccepted
                && record.state != ExecutionState::DispatchClaimed)
            {
                return Err(ScopeStoreError::InvalidTransition);
            }
            record.state = match outcome {
                Outcome::ApiAccepted => ExecutionState::ApiAccepted,
                Outcome::Rejected => ExecutionState::Rejected,
                Outcome::Unknown => ExecutionState::Unknown,
            };
            record.finished_at = Some(now);
            save_action(tx, &record)?;
            append_event(
                tx,
                &record.action.scope_id,
                Some(action_id),
                EventKind::AttemptFinished,
                Some(now),
                &record.digest,
            )?;
            Ok(record)
        })
    }

    /// Caller authorization to revoke is the trusted host's responsibility.
    pub fn revoke(&self, scope_id: &str, now: i64) -> Result<ScopeRecord, ScopeStoreError> {
        self.mutate(now, |tx| {
            let mut record = load_scope(tx, scope_id)?;
            if record.revoked_at.is_none() {
                record.revoked_at = Some(now);
                save_scope(tx, &record)?;
                append_event(
                    tx,
                    scope_id,
                    None,
                    EventKind::ScopeRevoked,
                    Some(now),
                    &record.digest,
                )?;
            }
            Ok(record)
        })
    }

    /// Host must authorize receipt disclosure; these are custody-level reads.
    pub fn get_scope(&self, scope_id: &str) -> Result<ScopeRecord, ScopeStoreError> {
        load_scope(&*self.connection()?, scope_id)
    }
    pub fn get_action(&self, action_id: &str) -> Result<ActionRecord, ScopeStoreError> {
        load_action(&*self.connection()?, action_id)
    }

    /// Complete retained evidence, atomically read under the ledger gate. This
    /// does not recover, retry, refund or grant anything. The trusted host owns
    /// auditor authentication and custody of the returned potentially sensitive
    /// resource/action metadata.
    pub fn export_evidence(&self) -> Result<ScopeEvidence, ScopeStoreError> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let (owner, last_seen) = metadata(&tx)?;
        if owner != self.owner {
            return Err(ScopeStoreError::OwnerMismatch);
        }
        check_export_size(&tx)?;
        let evidence = read_evidence(&tx, &owner, last_seen)?;
        evidence.encode().map_err(|_| ScopeStoreError::Corrupt)?;
        tx.commit()?;
        Ok(evidence)
    }

    /// Read a stopped ledger without performing startup recovery or creating a
    /// database. Requires the existing producer custody and exclusive writer
    /// lock. Pending records stay pending in the export; only broker startup
    /// records their interruption. Never copy a live database to use this API.
    pub fn export_stopped(
        path: &Path,
        owner: &AuthorityOwner,
    ) -> Result<ScopeEvidence, ScopeStoreError> {
        owner.validate()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let meta = parent.metadata()?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(ScopeStoreError::Corrupt);
        }
        // Existing regular custody files only; no repair or provisioning.
        fn existing(path: &Path) -> Result<File, ScopeStoreError> {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)?;
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.nlink() != 1
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.mode() & 0o077 != 0
            {
                return Err(ScopeStoreError::Corrupt);
            }
            Ok(file)
        }
        let _source = existing(path)?;
        let canonical = path.canonicalize()?;
        let mut lock_path = canonical.as_os_str().to_os_string();
        lock_path.push(".writer.lock");
        let lock = existing(Path::new(&lock_path))?;
        // SAFETY: this descriptor remains owned until the export is complete.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::WouldBlock {
                Err(ScopeStoreError::Locked)
            } else {
                Err(error.into())
            };
        }
        let _writer = WriterLock(lock);
        for suffix in ["-journal", "-wal", "-shm"] {
            let sibling = format!("{}{suffix}", canonical.display());
            if Path::new(&sibling).symlink_metadata().is_ok() {
                drop(existing(Path::new(&sibling))?);
            }
        }
        let mut connection =
            Connection::open_with_flags(&canonical, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.execute_batch("PRAGMA trusted_schema = OFF; PRAGMA query_only = ON;")?;
        let tx = connection.transaction()?;
        if tx.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))? != 1 {
            return Err(ScopeStoreError::Corrupt);
        }
        verify_schema(&tx)?;
        let (stored_owner, last_seen) = metadata(&tx)?;
        if stored_owner != *owner {
            return Err(ScopeStoreError::OwnerMismatch);
        }
        check_export_size(&tx)?;
        let evidence = read_evidence(&tx, owner, last_seen)?;
        evidence.encode().map_err(|_| ScopeStoreError::Corrupt)?;
        tx.commit()?;
        Ok(evidence)
    }

    pub fn get_request(
        &self,
        scope_id: &str,
        subject: &str,
        request_id: &str,
    ) -> Result<ActionRecord, ScopeStoreError> {
        let json:String=self.connection()?.query_row("SELECT record FROM scope_actions WHERE scope_id=?1 AND subject=?2 AND request_id=?3",params![scope_id,subject,request_id],|row|row.get(0)).optional()?.ok_or(ScopeStoreError::NotFound)?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Local append-only projection, not a signed portable evidence export.
    pub fn events(&self, after: u64, limit: usize) -> Result<Vec<AuthorityEvent>, ScopeStoreError> {
        if limit == 0 || limit > 1000 || after > i64::MAX as u64 {
            return Err(ScopeStoreError::Corrupt);
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT record FROM scope_events WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after as i64, limit as i64], |r| {
            r.get::<_, String>(0)
        })?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }

    /// Bounded historical projection. The host must authenticate an auditor.
    /// These records are evidence, never current authorization.
    pub fn snapshot(&self, limit: usize) -> Result<serde_json::Value, ScopeStoreError> {
        if limit == 0 || limit > 100 {
            return Err(ScopeStoreError::Corrupt);
        }
        let connection = self.connection()?;
        let mut projection = serde_json::Map::new();
        for (name, table, order) in [
            (
                "scopes",
                "scope_grants",
                "json_extract(record, '$.issued_at') DESC, id DESC",
            ),
            (
                "actions",
                "scope_actions",
                "json_extract(record, '$.reserved_at') DESC, id DESC",
            ),
            ("events", "scope_events", "sequence DESC"),
        ] {
            let total: u64 =
                connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })?;
            let mut statement = connection.prepare(&format!(
                "SELECT record FROM {table} ORDER BY {order} LIMIT ?1"
            ))?;
            let rows = statement.query_map([limit as i64], |row| row.get::<_, String>(0))?;
            let records: Vec<serde_json::Value> = rows
                .map(|row| Ok(serde_json::from_str(&row?)?))
                .collect::<Result<_, ScopeStoreError>>()?;
            projection.insert(name.into(), serde_json::json!(records));
            projection.insert(format!("{name}_total"), serde_json::json!(total));
        }
        Ok(serde_json::Value::Object(projection))
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, ScopeStoreError> {
        self.connection
            .as_ref()
            .ok_or(ScopeStoreError::Poisoned)?
            .lock()
            .map_err(|_| ScopeStoreError::Poisoned)
    }

    fn mutate<T>(
        &self,
        now: i64,
        operation: impl FnOnce(&Connection) -> Result<T, ScopeStoreError>,
    ) -> Result<T, ScopeStoreError> {
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, last_seen) = metadata(&tx)?;
        if now < last_seen {
            return Err(ScopeStoreError::ClockRollback);
        }
        // Preserve observed time even when the requested transition fails. An
        // expired attempt followed by a clock rollback cannot become active.
        tx.execute("UPDATE scope_meta SET last_seen = ?1 WHERE id = 1", [now])?;
        tx.execute_batch("SAVEPOINT scope_operation")?;
        let result = operation(&tx);
        if result.is_err() {
            tx.execute_batch("ROLLBACK TO scope_operation")?;
        }
        tx.execute_batch("RELEASE scope_operation")?;
        tx.commit()?;
        result
    }
}

fn custody_file(path: &Path) -> Result<File, ScopeStoreError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no memory preconditions.
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(ScopeStoreError::Corrupt);
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

fn verify_schema(connection: &Connection) -> Result<(), ScopeStoreError> {
    let mut statement = connection.prepare(
        "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let objects = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = [
        ("scope_actions", ACTIONS),
        ("scope_events", EVENTS),
        ("scope_grants", SCOPES),
        ("scope_meta", META),
    ];
    if objects.len() != expected.len()
        || !objects.iter().zip(expected).all(
            |((kind, name, sql), (expected_name, expected_sql))| {
                kind == "table" && name == expected_name && sql.as_deref() == Some(expected_sql)
            },
        )
    {
        return Err(ScopeStoreError::Corrupt);
    }
    Ok(())
}

fn metadata(connection: &Connection) -> Result<(AuthorityOwner, i64), ScopeStoreError> {
    let count: i64 = connection.query_row("SELECT count(*) FROM scope_meta", [], |r| r.get(0))?;
    if count != 1 {
        return Err(ScopeStoreError::Corrupt);
    }
    let (owner, time): (String, i64) = connection.query_row(
        "SELECT owner, last_seen FROM scope_meta WHERE id = 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let owner: AuthorityOwner = serde_json::from_str(&owner)?;
    owner.validate()?;
    if time < 0 {
        return Err(ScopeStoreError::Corrupt);
    }
    Ok((owner, time))
}

fn maybe_scope(connection: &Connection, id: &str) -> Result<Option<ScopeRecord>, ScopeStoreError> {
    let json: Option<String> = connection
        .query_row("SELECT record FROM scope_grants WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .optional()?;
    json.map(|json| {
        let record: ScopeRecord = serde_json::from_str(&json)?;
        if record.grant.scope_id != id
            || record.grant != record.grant.canonicalized()?
            || record.digest != record.grant.digest()?
        {
            return Err(ScopeStoreError::Corrupt);
        }
        Ok(record)
    })
    .transpose()
}
fn load_scope(connection: &Connection, id: &str) -> Result<ScopeRecord, ScopeStoreError> {
    maybe_scope(connection, id)?.ok_or(ScopeStoreError::NotFound)
}
fn save_scope(connection: &Connection, record: &ScopeRecord) -> Result<(), ScopeStoreError> {
    if connection.execute(
        "UPDATE scope_grants SET record = ?1 WHERE id = ?2",
        params![serde_json::to_string(record)?, record.grant.scope_id],
    )? != 1
    {
        return Err(ScopeStoreError::Corrupt);
    }
    Ok(())
}
fn load_action(connection: &Connection, id: &str) -> Result<ActionRecord, ScopeStoreError> {
    let row: Option<(String, String, String, String)> = connection
        .query_row(
            "SELECT scope_id, subject, request_id, record FROM scope_actions WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let (scope, subject, request, json) = row.ok_or(ScopeStoreError::NotFound)?;
    let record: ActionRecord = serde_json::from_str(&json)?;
    if record.action.action_id != id
        || record.action.scope_id != scope
        || record.action.subject != subject
        || record.action.request_id != request
        || record.action != record.action.canonicalized()?
        || record.digest != record.action.digest()?
    {
        return Err(ScopeStoreError::Corrupt);
    }
    Ok(record)
}
fn save_action(connection: &Connection, record: &ActionRecord) -> Result<(), ScopeStoreError> {
    if connection.execute(
        "UPDATE scope_actions SET record = ?1 WHERE id = ?2",
        params![serde_json::to_string(record)?, record.action.action_id],
    )? != 1
    {
        return Err(ScopeStoreError::Corrupt);
    }
    Ok(())
}
fn all_actions(connection: &Connection) -> Result<Vec<ActionRecord>, ScopeStoreError> {
    let mut statement = connection.prepare("SELECT id FROM scope_actions ORDER BY id")?;
    let ids = statement
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    ids.iter().map(|id| load_action(connection, id)).collect()
}
fn chain(connection: &Connection, id: &str) -> Result<Vec<ScopeRecord>, ScopeStoreError> {
    let mut result = Vec::new();
    let mut current = Some(id.to_owned());
    while let Some(id) = current {
        if result.len() > MAX_DEPTH as usize
            || result.iter().any(|r: &ScopeRecord| r.grant.scope_id == id)
        {
            return Err(ScopeStoreError::Corrupt);
        }
        let record = load_scope(connection, &id)?;
        current = record.grant.parent_id.clone();
        result.push(record);
    }
    for pair in result.windows(2) {
        pair[0].grant.validate_child_of(&pair[1].grant)?;
    }
    Ok(result)
}
fn active_chain(
    connection: &Connection,
    id: &str,
    now: i64,
) -> Result<Vec<ScopeRecord>, ScopeStoreError> {
    let result = chain(connection, id)?;
    if result
        .iter()
        .any(|r| r.revoked_at.is_some() || now < r.grant.not_before || now >= r.grant.expires_at)
    {
        return Err(ScopeStoreError::Inactive);
    }
    Ok(result)
}
fn append_event(
    connection: &Connection,
    scope: &str,
    action: Option<&str>,
    kind: EventKind,
    at: Option<i64>,
    digest: &str,
) -> Result<(), ScopeStoreError> {
    let previous: i64 = connection.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM scope_events",
        [],
        |r| r.get(0),
    )?;
    let sequence = previous.checked_add(1).ok_or(ScopeStoreError::Corrupt)?;
    let event = AuthorityEvent {
        sequence: sequence as u64,
        scope_id: scope.into(),
        action_id: action.map(str::to_owned),
        kind,
        observed_at: at,
        content_digest: digest.into(),
    };
    connection.execute(
        "INSERT INTO scope_events VALUES (?1, ?2)",
        params![sequence, serde_json::to_string(&event)?],
    )?;
    Ok(())
}

fn check_export_size(connection: &Connection) -> Result<(), ScopeStoreError> {
    // Bound serialized rows before materializing them. Never silently truncate.
    let bytes: u64 = connection.query_row("SELECT (SELECT coalesce(sum(length(CAST(record AS BLOB))),0) FROM scope_grants) + (SELECT coalesce(sum(length(CAST(record AS BLOB))),0) FROM scope_actions) + (SELECT coalesce(sum(length(CAST(record AS BLOB))),0) FROM scope_events)", [], |row| row.get(0))?;
    if bytes > opaque_core::evidence_checkpoint::MAX_EXPORT_BYTES as u64 {
        return Err(ScopeStoreError::Corrupt);
    }
    Ok(())
}

fn read_evidence(
    connection: &Connection,
    owner: &AuthorityOwner,
    last_seen: i64,
) -> Result<ScopeEvidence, ScopeStoreError> {
    let mut statement = connection.prepare("SELECT id FROM scope_grants ORDER BY id")?;
    let ids = statement
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let scopes = ids
        .iter()
        .map(|id| load_scope(connection, id))
        .collect::<Result<Vec<_>, _>>()?;
    let mut statement =
        connection.prepare("SELECT sequence, record FROM scope_events ORDER BY sequence")?;
    let mut events = Vec::new();
    for row in statement.query_map([], |r| Ok((r.get::<_, u64>(0)?, r.get::<_, String>(1)?)))? {
        let (sequence, json) = row?;
        let event: AuthorityEvent = serde_json::from_str(&json)?;
        if event.sequence != sequence {
            return Err(ScopeStoreError::Corrupt);
        }
        events.push(event);
    }
    Ok(ScopeEvidence {
        schema_version: 1,
        owner: owner.clone(),
        last_seen,
        scopes,
        actions: all_actions(connection)?,
        events,
    })
}

fn verify_all(
    connection: &Connection,
    owner: &AuthorityOwner,
    last_seen: i64,
) -> Result<(), ScopeStoreError> {
    read_evidence(connection, owner, last_seen)?
        .validate()
        .map_err(|_| ScopeStoreError::Corrupt)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
