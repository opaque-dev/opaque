//! Fixed support-case status protocol. Trusted configuration selects the server;
//! agent input cannot select a URL, header, credential, method, or arbitrary body.
use super::custody::{self, Contract};
use opaque_bounded_work::scope_store::Outcome;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub const OPERATION: &str = "support.case.set_status";
const CONTRACT: Contract = Contract {
    noun: "support",
    contract: "opaque.support.case.v1",
    profile_domain: "opaque.support.provider-profile",
    credential_domain: "opaque.support.credential.v1",
};
/// Shared by every scope connector: the sealed profile selects the HTTPS base,
/// the broker-owned credential file and optional operator PEM trust roots.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub endpoint: String,
    pub token_file: PathBuf,
    /// Operator-owned PEM roots. When present these replace built-in roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_certificate_file: Option<PathBuf>,
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
        let loaded = custody::load(profile, &CONTRACT)?;
        Ok(Self {
            client: loaded.client,
            endpoint: loaded.endpoint,
            authorization: loaded.authorization,
            digest: loaded.digest,
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
