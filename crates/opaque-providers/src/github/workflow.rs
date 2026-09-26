//! GitHub Actions `workflow_dispatch` protocol shared by the bounded staging
//! task family and the scoped-authority runtime. Callers own credential
//! custody, TLS trust, policy, human approval, reservation and the durable
//! at-most-once dispatch claim; this module only speaks the fixed API shape.
use serde::Deserialize;

pub const API_VERSION: &str = "2026-03-10";
/// Typed read responses are small; anything larger is not the expected object.
pub const MAX_READ_BYTES: usize = 64 * 1024;

/// One dispatch target: `owner/repo`, a workflow file and a branch name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target<'a> {
    pub repository: &'a str,
    pub path: &'a str,
    pub git_ref: &'a str,
}
impl Target<'_> {
    pub fn validate(&self) -> Result<(), String> {
        opaque_core::release::validate_repository(self.repository)?;
        opaque_core::release::validate_workflow_path(self.path)?;
        opaque_core::release::validate_branch(self.git_ref)?;
        Ok(())
    }
    fn file_name(&self) -> Result<&str, String> {
        self.path
            .rsplit('/')
            .next()
            .ok_or_else(|| "invalid workflow path".into())
    }
}

/// Fixed headers every GitHub REST request carries.
pub fn headers(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    builder
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", API_VERSION)
        .header("user-agent", "opaqued")
}

/// `{base}/repos/{owner}/{repo}/{suffix...}` built from path segments, never
/// from string concatenation, so a component cannot introduce a separator.
pub fn repository_url(
    base: &reqwest::Url,
    repository: &str,
    suffix: &[&str],
) -> Result<reqwest::Url, String> {
    let (owner, repo) = repository
        .split_once('/')
        .ok_or("invalid repository identity")?;
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| "invalid GitHub API base")?;
        path.pop_if_empty()
            .extend(["repos", owner, repo])
            .extend(suffix.iter().copied());
    }
    Ok(url)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Workflow {
    pub id: u64,
    pub path: String,
    pub state: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Commit {
    pub sha: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Branch {
    pub name: String,
    pub protected: bool,
    pub commit: Commit,
}

async fn read<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: reqwest::Url,
    authorization: &reqwest::header::HeaderValue,
) -> Result<T, String> {
    let mut response = headers(http.get(url))
        .header(reqwest::header::AUTHORIZATION, authorization.clone())
        .send()
        .await
        .map_err(|_| "GitHub read unavailable")?;
    if response.status() != reqwest::StatusCode::OK
        || response
            .content_length()
            .is_some_and(|n| n > MAX_READ_BYTES as u64)
    {
        return Err("GitHub read unavailable".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "GitHub read unavailable")?
    {
        if bytes.len() + chunk.len() > MAX_READ_BYTES {
            return Err("GitHub response too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid GitHub response".into())
}

/// `GET /repos/{owner}/{repo}/actions/workflows/{file}`; the returned path must
/// name the requested file and the workflow must be active.
pub async fn read_workflow(
    http: &reqwest::Client,
    base: &reqwest::Url,
    target: &Target<'_>,
    authorization: &reqwest::header::HeaderValue,
) -> Result<Workflow, String> {
    target.validate()?;
    let url = repository_url(
        base,
        target.repository,
        &["actions", "workflows", target.file_name()?],
    )?;
    let workflow: Workflow = read(http, url, authorization).await?;
    if workflow.id == 0 || workflow.path != target.path || workflow.state != "active" {
        return Err("GitHub workflow mismatch or inactive".into());
    }
    Ok(workflow)
}

/// `GET /repos/{owner}/{repo}/branches/{ref}`; the head commit is the version
/// a reviewer sees. GitHub does not enforce it as a dispatch precondition.
pub async fn read_branch(
    http: &reqwest::Client,
    base: &reqwest::Url,
    target: &Target<'_>,
    authorization: &reqwest::header::HeaderValue,
) -> Result<Branch, String> {
    target.validate()?;
    let url = repository_url(base, target.repository, &["branches", target.git_ref])?;
    let branch: Branch = read(http, url, authorization).await?;
    if branch.name != target.git_ref
        || branch.commit.sha.len() != 40
        || !branch
            .commit
            .sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("GitHub branch mismatch".into());
    }
    Ok(branch)
}

/// `workflow_dispatch` accepts a branch OR tag name. Refuse a name that also
/// exists as a tag instead of assuming which one GitHub selects.
pub async fn tag_absent(
    http: &reqwest::Client,
    base: &reqwest::Url,
    target: &Target<'_>,
    authorization: &reqwest::header::HeaderValue,
) -> Result<(), String> {
    target.validate()?;
    let url = repository_url(
        base,
        target.repository,
        &["git", "ref", "tags", target.git_ref],
    )?;
    let response = headers(http.get(url))
        .header(reqwest::header::AUTHORIZATION, authorization.clone())
        .send()
        .await
        .map_err(|_| "GitHub read unavailable")?;
    if response.status() != reqwest::StatusCode::NOT_FOUND {
        return Err("branch name is ambiguous with a tag".into());
    }
    Ok(())
}

/// What one `POST .../dispatches` attempt established. `Accepted` is an API
/// acknowledgment (204, no run id), never workflow completion. `Rejected` means
/// GitHub validated and refused, so no run was created. Everything else is
/// `Unknown`: the request may or may not have dispatched, and there is no
/// idempotency key to make a second attempt safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acknowledgment {
    Accepted,
    Rejected,
    Unknown,
}
pub fn acknowledge(result: Result<reqwest::Response, reqwest::Error>) -> Acknowledgment {
    match result {
        Ok(response) if response.status().is_success() => Acknowledgment::Accepted,
        Ok(response)
            if response.status().is_client_error() && response.status().as_u16() != 408 =>
        {
            Acknowledgment::Rejected
        }
        _ => Acknowledgment::Unknown,
    }
}

/// Exactly one `POST /repos/{owner}/{repo}/actions/workflows/{file}/dispatches`
/// with `{"ref": ref}` and no inputs. The caller must have consumed its dispatch
/// claim before calling; a returned `Unknown` must never be retried automatically.
pub async fn dispatch(
    http: &reqwest::Client,
    base: &reqwest::Url,
    target: &Target<'_>,
    authorization: &reqwest::header::HeaderValue,
) -> Acknowledgment {
    if target.validate().is_err() {
        return Acknowledgment::Unknown;
    }
    let Ok(file) = target.file_name() else {
        return Acknowledgment::Unknown;
    };
    let Ok(url) = repository_url(
        base,
        target.repository,
        &["actions", "workflows", file, "dispatches"],
    ) else {
        return Acknowledgment::Unknown;
    };
    acknowledge(
        headers(http.post(url))
            .header(reqwest::header::AUTHORIZATION, authorization.clone())
            .json(&serde_json::json!({"ref": target.git_ref}))
            .send()
            .await,
    )
}
