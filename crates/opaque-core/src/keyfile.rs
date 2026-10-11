//! Shared 32-byte key-file custody: create with CSPRNG on first use, 0600,
//! load thereafter. Backs the seal key, the pairing-store integrity key, and
//! any future file-custody key. Under the trust-domain split these files are
//! exactly what the agent's uid cannot read — which is what upgrades the
//! constructs they key from tamper-evident to tamper-proof.

use std::io;
use std::path::Path;

/// Load the 32-byte key at `path`, creating it (0600, CSPRNG) if absent.
///
/// A present-but-wrong-length file is corruption and errors — it never
/// silently regenerates, because a regenerated key would orphan everything
/// the old key authenticated.
pub fn load_or_create_key_file(path: &Path) -> io::Result<[u8; 32]> {
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("key file {} is corrupt (wrong length)", path.display()),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    // 32 key bytes plus 8 bytes that only name the temporary file.
    let mut random = [0u8; 40];
    getrandom::fill(&mut random)
        .map_err(|e| io::Error::other(format!("failed to generate key: {e}")))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&random[..32]);
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&random[32..]);
    write_key_file(path, &key, u64::from_le_bytes(nonce))?;
    Ok(key)
}

/// Load the 32-byte key at `path` if it exists (`Ok(None)` when absent).
pub fn load_key_file(path: &Path) -> io::Result<Option<[u8; 32]>> {
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(Some(key))
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("key file {} is corrupt (wrong length)", path.display()),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write the key under a temporary name, fsync it, link it into place and
/// fsync the directory, so `path` only ever appears holding all 32 bytes. A
/// power cut before that leaves no key, which the next start creates; writing
/// `path` in place could leave a short file, which every start then refuses.
/// Linking, unlike rename, fails instead of replacing a key that another
/// creator placed first, so an existing key is never orphaned.
#[cfg(unix)]
fn write_key_file(path: &Path, key: &[u8; 32], nonce: u64) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".{nonce:016x}.tmp"));
    let temporary = std::path::PathBuf::from(temporary);
    let placed = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(key)?;
        file.sync_all()?;
        std::fs::hard_link(&temporary, path)
    })();
    let _ = std::fs::remove_file(&temporary);
    placed?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    std::fs::File::open(parent.unwrap_or(Path::new(".")))?.sync_all()
}

#[cfg(not(unix))]
fn write_key_file(path: &Path, key: &[u8; 32], _nonce: u64) -> io::Result<()> {
    std::fs::write(path, key)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn creates_then_reloads_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("some.key");
        let first = load_or_create_key_file(&path).unwrap();
        let second = load_or_create_key_file(&path).unwrap();
        assert_eq!(first, second);
        assert_eq!(load_key_file(&path).unwrap(), Some(first));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // The temporary name is gone; only the key remains.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("some.key")]);
    }

    #[cfg(unix)]
    #[test]
    fn placing_a_key_never_replaces_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("some.key");
        std::fs::write(&path, [7u8; 32]).unwrap();
        let error = write_key_file(&path, &[9u8; 32], 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), [7u8; 32]);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn missing_directory_fails_without_creating_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent").join("some.key");
        let error = load_or_create_key_file(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(!path.exists());
    }

    #[test]
    fn corrupt_key_errors_rather_than_regenerating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("some.key");
        std::fs::write(&path, b"short").unwrap();
        assert!(load_or_create_key_file(&path).is_err());
        assert!(load_key_file(&path).is_err());
        // The corrupt file is left in place for the operator to inspect.
        assert_eq!(std::fs::read(&path).unwrap(), b"short");
    }

    #[test]
    fn absent_key_is_none_for_load_only() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_key_file(&dir.path().join("nope.key")).unwrap(), None);
    }
}
