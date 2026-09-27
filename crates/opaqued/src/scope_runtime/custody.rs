//! Broker-custody loading shared by every scope connector: a fixed HTTPS base,
//! a private single-link credential file, optional operator PEM trust roots,
//! and one provider-profile digest that binds all three without exposing a
//! separate credential fingerprint. Agent input never reaches this module.
use super::connector::Profile;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    time::Duration,
};

/// Fixed identity of one connector protocol. Domain strings are distinct per
/// protocol so a support profile digest can never equal a GitHub one.
pub struct Contract {
    /// Noun for error messages, for example `support` or `GitHub`.
    pub noun: &'static str,
    /// Protocol identifier bound into the profile, for example `opaque.support.case.v1`.
    pub contract: &'static str,
    /// Digest domain prefix; `.v2` (public roots) or `.v3` (configured roots) is appended.
    pub profile_domain: &'static str,
    /// Credential commitment domain, NUL terminated by this module.
    pub credential_domain: &'static str,
}

pub struct Loaded {
    pub client: reqwest::Client,
    pub endpoint: reqwest::Url,
    pub authorization: reqwest::header::HeaderValue,
    pub digest: String,
}

fn private_file(
    path: &std::path::Path,
    limit: u64,
    unavailable: &str,
    invalid: &str,
) -> Result<std::fs::File, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| unavailable.to_owned())?;
    let meta = file.metadata().map_err(|_| unavailable.to_owned())?;
    // SAFETY: geteuid has no preconditions.
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || meta.len() > limit
    {
        return Err(invalid.to_owned());
    }
    Ok(file)
}

pub fn load(profile: &Profile, contract: &Contract) -> Result<Loaded, String> {
    let noun = contract.noun;
    let endpoint =
        reqwest::Url::parse(&profile.endpoint).map_err(|_| format!("invalid {noun} endpoint"))?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !endpoint.path().ends_with('/')
    {
        return Err(format!(
            "{noun} endpoint must be a fixed HTTPS base ending in slash"
        ));
    }
    if !profile.token_file.is_absolute() {
        return Err(format!(
            "{noun} credential requires an absolute private path"
        ));
    }
    let file = private_file(
        &profile.token_file,
        4096,
        &format!("{noun} credential unavailable"),
        &format!("{noun} credential custody invalid"),
    )?;
    let mut token = zeroize::Zeroizing::new(String::new());
    file.take(4097)
        .read_to_string(&mut token)
        .map_err(|_| format!("{noun} credential invalid"))?;
    if token.len() > 4096 {
        return Err(format!("{noun} credential invalid"));
    }
    let token = token.trim();
    if token.is_empty()
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.~+/=".contains(&b))
    {
        return Err(format!("{noun} credential invalid"));
    }
    let authorization_text = zeroize::Zeroizing::new(format!("Bearer {token}"));
    let mut authorization = reqwest::header::HeaderValue::from_str(&authorization_text)
        .map_err(|_| format!("{noun} credential invalid"))?;
    authorization.set_sensitive(true);
    // A path identifies custody, not the provider account selected by its
    // current credential. Keep this credential commitment internal; only the
    // enclosing provider-profile digest leaves the connector.
    let mut credential_hash = Sha256::new();
    credential_hash.update(contract.credential_domain.as_bytes());
    credential_hash.update([0]);
    credential_hash.update(token.as_bytes());
    let credential_binding = zeroize::Zeroizing::new(<[u8; 32]>::from(credential_hash.finalize()));
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(8));
    let ca_digest = if let Some(path) = &profile.ca_certificate_file {
        if !path.is_absolute() {
            return Err(format!("{noun} CA requires an absolute private path"));
        }
        let mut file = private_file(
            path,
            65536,
            &format!("{noun} CA unavailable"),
            &format!("{noun} CA custody invalid"),
        )?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| format!("{noun} CA unavailable"))?;
        if bytes.len() > 65536 {
            return Err(format!("{noun} CA exceeds 64 KiB"));
        }
        let certificates = reqwest::Certificate::from_pem_bundle(&bytes)
            .map_err(|_| format!("invalid {noun} CA PEM"))?;
        if certificates.is_empty() || certificates.len() > 16 {
            return Err(format!(
                "{noun} CA requires one to sixteen PEM certificates"
            ));
        }
        builder = builder.tls_built_in_root_certs(false);
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
        Some(<[u8; 32]>::from(Sha256::digest(&bytes)))
    } else {
        None
    };
    let client = builder
        .build()
        .map_err(|_| format!("{noun} transport unavailable"))?;
    let mut profile_value = serde_json::json!({"contract":contract.contract,"endpoint":endpoint.as_str(),"credential_slot":profile.token_file});
    if let Some(path) = &profile.ca_certificate_file {
        profile_value["ca_certificate_slot"] = serde_json::json!(path);
        profile_value["tls_trust"] = serde_json::json!("configured_pem_only");
    }
    let profile_bytes = serde_json::to_vec(&profile_value).map_err(|_| "encoding failed")?;
    let mut profile_hash = Sha256::new();
    profile_hash.update(contract.profile_domain.as_bytes());
    profile_hash.update(if ca_digest.is_some() { b".v3" } else { b".v2" });
    profile_hash.update([0]);
    profile_hash.update((profile_bytes.len() as u64).to_be_bytes());
    profile_hash.update(&profile_bytes);
    profile_hash.update(credential_binding.as_ref());
    if let Some(digest) = ca_digest {
        profile_hash.update(digest);
    }
    Ok(Loaded {
        client,
        endpoint,
        authorization,
        digest: format!("{:x}", profile_hash.finalize()),
    })
}
