//! Fixed support-case status protocol. Trusted configuration selects the server;
//! agent input cannot select a URL, header, credential, method, or arbitrary body.
use opaque_bounded_work::scope_store::Outcome;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    time::Duration,
};

pub const OPERATION: &str = "support.case.set_status";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub endpoint: String,
    pub token_file: PathBuf,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub status: Status,
    pub version: String,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    Resolved,
    Closed,
}
impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Resolved => "resolved",
            Self::Closed => "closed",
        }
    }
}
#[derive(Clone)]
pub struct Connector {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    authorization: reqwest::header::HeaderValue,
    pub digest: String,
}
pub fn identifier(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err("invalid support case identifier or version".into());
    }
    Ok(())
}
pub fn hash(value: &impl Serialize) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(|_| "encoding failed")?)
    ))
}
impl Connector {
    pub fn new(profile: &Profile) -> Result<Self, String> {
        Self::build(profile, None)
    }
    #[cfg(test)]
    pub fn new_with_certificate(profile: &Profile, certificate: &[u8]) -> Result<Self, String> {
        Self::build(profile, Some(certificate))
    }
    fn build(profile: &Profile, certificate: Option<&[u8]>) -> Result<Self, String> {
        let endpoint =
            reqwest::Url::parse(&profile.endpoint).map_err(|_| "invalid support endpoint")?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !endpoint.path().ends_with('/')
        {
            return Err("support endpoint must be a fixed HTTPS base ending in slash".into());
        }
        if !profile.token_file.is_absolute() {
            return Err("support credential requires an absolute private path".into());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&profile.token_file)
            .map_err(|_| "support credential unavailable")?;
        let meta = file
            .metadata()
            .map_err(|_| "support credential unavailable")?;
        // SAFETY: geteuid has no preconditions.
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
            || meta.nlink() != 1
            || meta.len() > 4096
        {
            return Err("support credential custody invalid".into());
        }
        let mut token = zeroize::Zeroizing::new(String::new());
        file.take(4097)
            .read_to_string(&mut token)
            .map_err(|_| "support credential invalid")?;
        if token.len() > 4096 {
            return Err("support credential invalid".into());
        }
        let token = token.trim();
        if token.is_empty()
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.~+/=".contains(&b))
        {
            return Err("support credential invalid".into());
        }
        let authorization_text = zeroize::Zeroizing::new(format!("Bearer {token}"));
        let mut authorization = reqwest::header::HeaderValue::from_str(&authorization_text)
            .map_err(|_| "support credential invalid")?;
        authorization.set_sensitive(true);
        // A path identifies custody, not the provider account selected by its
        // current credential. Keep this credential commitment internal; only
        // the enclosing provider-profile digest leaves the connector.
        let mut credential_hash = Sha256::new();
        credential_hash.update(b"opaque.support.credential.v1\0");
        credential_hash.update(token.as_bytes());
        let credential_binding =
            zeroize::Zeroizing::new(<[u8; 32]>::from(credential_hash.finalize()));
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(8));
        if let Some(certificate) = certificate {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_der(certificate)
                    .map_err(|_| "invalid support test certificate")?,
            );
        }
        let client = builder
            .build()
            .map_err(|_| "support transport unavailable")?;
        let profile_bytes = serde_json::to_vec(
            &serde_json::json!({"contract":"opaque.support.case.v1","endpoint":endpoint.as_str(),"credential_slot":profile.token_file}),
        ).map_err(|_| "encoding failed")?;
        let mut profile_hash = Sha256::new();
        profile_hash.update(b"opaque.support.provider-profile.v2\0");
        profile_hash.update((profile_bytes.len() as u64).to_be_bytes());
        profile_hash.update(&profile_bytes);
        profile_hash.update(credential_binding.as_ref());
        let digest = format!("{:x}", profile_hash.finalize());
        Ok(Self {
            client,
            endpoint,
            authorization,
            digest,
        })
    }
    fn url(&self, id: &str) -> Result<reqwest::Url, String> {
        identifier(id)?;
        self.endpoint
            .join(&format!("cases/{id}"))
            .map_err(|_| "invalid support resource".into())
    }
    pub async fn read(&self, id: &str) -> Result<Case, String> {
        let mut response = self
            .client
            .get(self.url(id)?)
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
            .send()
            .await
            .map_err(|_| "support read unavailable")?;
        if response.status() != reqwest::StatusCode::OK
            || response.content_length().is_some_and(|n| n > 16384)
        {
            return Err("support read unavailable".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "support read unavailable")?
        {
            if bytes.len() + chunk.len() > 16384 {
                return Err("support response too large".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let case: Case = serde_json::from_slice(&bytes).map_err(|_| "invalid support response")?;
        identifier(&case.id)?;
        identifier(&case.version)?;
        if case.id != id {
            return Err("support resource mismatch".into());
        }
        Ok(case)
    }
    pub async fn write(&self, id: &str, version: &str, status: Status, action_id: &str) -> Outcome {
        let Ok(url) = self.url(id) else {
            return Outcome::Unknown;
        };
        if identifier(version).is_err() || identifier(action_id).is_err() {
            return Outcome::Unknown;
        }
        // Exactly one attempt. A connection error, redirect, server error, or
        // unexpected response is UNKNOWN and never results in automatic retry.
        match self
            .client
            .patch(url)
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
            .header(reqwest::header::IF_MATCH, format!("\"{version}\""))
            .header("Idempotency-Key", action_id)
            .json(&serde_json::json!({"status":status}))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => Outcome::ApiAccepted,
            Ok(response) if matches!(response.status().as_u16(), 409 | 412) => Outcome::Rejected,
            _ => Outcome::Unknown,
        }
    }
}
