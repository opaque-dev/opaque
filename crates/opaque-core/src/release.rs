//! Typed authority and read-only evidence for one staging workflow dispatch.

use serde::{Deserialize, Serialize};

pub const STAGING_RELEASE_OPERATION: &str = "github.dispatch_staging_workflow";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagingReleaseAction {
    pub operation: String,
    pub repo: String,
    #[serde(default)]
    pub repository_id: u64,
    pub workflow_path: String,
    #[serde(default)]
    pub workflow_id: u64,
    /// A branch name, never a tag, SHA, or arbitrary ref expression.
    pub workflow_ref: String,
    #[serde(default)]
    pub approved_commit_sha: String,
    /// SHA-256 of the exact reviewed workflow bytes; bound by trusted config.
    #[serde(default)]
    pub workflow_sha256: String,
    pub image_repository: String,
    pub image_digest: String,
    pub environment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_token_ref: Option<String>,
}

/// `owner/repo` with the component character set GitHub accepts. Shared by
/// the staging task family and the scoped `github.workflow.dispatch` kind.
pub fn validate_repository(repo: &str) -> Result<(), &'static str> {
    let components: Vec<_> = repo.split('/').collect();
    if components.len() != 2
        || components.iter().any(|part| {
            part.is_empty()
                || part.len() > 100
                || *part == "."
                || *part == ".."
                || !part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        })
    {
        return Err("invalid staging repository or workflow identity");
    }
    Ok(())
}

/// A workflow file directly under `.github/workflows/`, never a nested path.
pub fn validate_workflow_path(path: &str) -> Result<(), &'static str> {
    let filename = path
        .strip_prefix(".github/workflows/")
        .ok_or("invalid staging workflow path")?;
    if filename.is_empty()
        || filename.len() > 100
        || !(filename.ends_with(".yml") || filename.ends_with(".yaml"))
        || !filename
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
    {
        return Err("invalid staging workflow path");
    }
    Ok(())
}

/// A branch name, never a tag, SHA, `refs/` path or arbitrary ref expression.
pub fn validate_branch(branch: &str) -> Result<(), &'static str> {
    if branch.is_empty()
        || branch.len() > 200
        || branch.starts_with("refs/")
        || branch.ends_with('.')
        || branch.ends_with('/')
        || branch.contains("..")
        || branch.contains("//")
        || branch
            .split('/')
            .any(|p| p.is_empty() || p.starts_with('.') || p.ends_with(".lock"))
        || !branch
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_/.".contains(&c))
        || hex_lower(branch, 40)
    {
        return Err("invalid staging branch");
    }
    Ok(())
}

impl StagingReleaseAction {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.operation != STAGING_RELEASE_OPERATION {
            return Err("invalid staging release operation");
        }
        validate_repository(&self.repo)?;
        if self.repository_id == 0 || self.workflow_id == 0 {
            return Err("invalid staging repository or workflow identity");
        }
        validate_workflow_path(&self.workflow_path)?;
        validate_branch(&self.workflow_ref)?;
        if !hex_lower(&self.approved_commit_sha, 40) || !hex_lower(&self.workflow_sha256, 64) {
            return Err("invalid staging commit or workflow digest");
        }
        let image = &self.image_repository;
        if image.is_empty()
            || image.len() > 255
            || !image.contains('/')
            || image.starts_with('/')
            || image.ends_with('/')
            || image.contains("//")
            || image.split('/').any(|p| p == "." || p == "..")
            || !image
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"/._-".contains(&c))
            || !self
                .image_digest
                .strip_prefix("sha256:")
                .is_some_and(|s| hex_lower(s, 64))
            || self.environment != "staging"
        {
            return Err("invalid staging image or destination");
        }
        crate::task::validate_github_token_ref(
            self.github_token_ref
                .as_deref()
                .ok_or("invalid staging credential reference")?,
        )
        .map_err(|_| "invalid staging credential reference")?;
        Ok(())
    }
}

fn hex_lower(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A workflow result is evidence about GitHub execution, not proof that a
/// service became healthy. Only the reviewed workflow defines its success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseObservationState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseCorrelation {
    DispatchResponse,
    TaskTitle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseObservation {
    pub state: ReleaseObservationState,
    pub correlation: ReleaseCorrelation,
    /// Provider-generated fixed code. Never provider response text.
    pub code: String,
    pub run_id: Option<u64>,
    /// Constructed from trusted authority and validated identity.
    pub run_url: Option<String>,
    pub observed_commit_sha: Option<String>,
    pub checked_at: i64,
    pub run_attempt: Option<u64>,
}

impl ReleaseObservation {
    pub fn validate(
        &self,
        action: &StagingReleaseAction,
        github_api_url: &str,
    ) -> Result<(), String> {
        let invalid = || "invalid release observation".to_owned();
        action.validate().map_err(|_| invalid())?;
        if self.checked_at <= 0 {
            return Err(invalid());
        }
        let valid_code = match self.state {
            ReleaseObservationState::Pending => self.code == "run_not_observed",
            ReleaseObservationState::Running => self.code == "run_in_progress",
            ReleaseObservationState::Succeeded => self.code == "workflow_succeeded",
            ReleaseObservationState::Failed => self.code == "workflow_failed",
            ReleaseObservationState::Ambiguous => matches!(
                self.code.as_str(),
                "run_correlation_ambiguous" | "external_rerun_observed" | "run_evidence_mismatch"
            ),
        };
        if !valid_code {
            return Err(invalid());
        }
        match (
            self.run_id,
            &self.run_url,
            &self.observed_commit_sha,
            self.run_attempt,
        ) {
            (Some(id), Some(url), Some(sha), Some(attempt)) => {
                if id == 0
                    || attempt == 0
                    || sha != &action.approved_commit_sha
                    || url
                        != &format!(
                            "{}/repos/{}/actions/runs/{id}",
                            github_api_url.trim_end_matches('/'),
                            action.repo
                        )
                    || (attempt > 1
                        && (self.state != ReleaseObservationState::Ambiguous
                            || self.code != "external_rerun_observed"))
                    || (attempt == 1 && self.code == "external_rerun_observed")
                    || self.state == ReleaseObservationState::Pending
                {
                    return Err(invalid());
                }
            }
            (None, None, None, None) => {
                if !matches!(
                    self.state,
                    ReleaseObservationState::Pending | ReleaseObservationState::Ambiguous
                ) || self.code == "external_rerun_observed"
                {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn action() -> StagingReleaseAction {
        StagingReleaseAction {
            operation: STAGING_RELEASE_OPERATION.into(),
            repo: "owner/app".into(),
            repository_id: 1,
            workflow_path: ".github/workflows/staging.yml".into(),
            workflow_id: 2,
            workflow_ref: "main".into(),
            approved_commit_sha: "a".repeat(40),
            workflow_sha256: "b".repeat(64),
            image_repository: "ghcr.io/owner/app".into(),
            image_digest: format!("sha256:{}", "c".repeat(64)),
            environment: "staging".into(),
            github_token_ref: Some("keychain:opaque/github-pat".into()),
        }
    }

    #[test]
    fn release_restricts_destination_artifact_and_ref_expressions() {
        assert!(action().validate().is_ok());
        let mutations: [fn(&mut StagingReleaseAction); 14] = [
            |a| a.operation = "github.arbitrary".into(),
            |a| a.repo = "owner/../app".into(),
            |a| a.workflow_path = ".github/workflows/../unsafe.yml".into(),
            |a| a.workflow_ref = "refs/tags/v1".into(),
            |a| a.workflow_ref = "main~1".into(),
            |a| a.workflow_ref = "a".repeat(40),
            |a| a.approved_commit_sha = "HEAD".into(),
            |a| a.workflow_sha256 = "B".repeat(64),
            |a| a.image_repository = "ghcr.io/owner/app:latest".into(),
            |a| a.image_digest = "latest".into(),
            |a| a.environment = "production".into(),
            |a| a.github_token_ref = Some("raw-token".into()),
            |a| a.github_token_ref = Some(format!("env:{}", "x".repeat(129))),
            |a| a.github_token_ref = Some("vault:kv/data/credentials#PAT".into()),
        ];
        for mutate in mutations {
            let mut invalid = action();
            mutate(&mut invalid);
            assert!(invalid.validate().is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn release_rejects_arbitrary_inputs() {
        let mut value = serde_json::to_value(action()).unwrap();
        value["inputs"] = serde_json::json!({"command": "arbitrary"});
        assert!(serde_json::from_value::<StagingReleaseAction>(value).is_err());
    }

    #[test]
    fn observations_only_expose_bound_links_and_honest_rerun_state() {
        let action = action();
        let mut observed = ReleaseObservation {
            state: ReleaseObservationState::Succeeded,
            correlation: ReleaseCorrelation::DispatchResponse,
            code: "workflow_succeeded".into(),
            run_id: Some(23),
            run_url: Some("https://api.github.com/repos/owner/app/actions/runs/23".into()),
            observed_commit_sha: Some(action.approved_commit_sha.clone()),
            checked_at: 1,
            run_attempt: Some(1),
        };
        observed
            .validate(&action, "https://api.github.com")
            .unwrap();
        observed.run_url = Some("https://attacker.invalid/click".into());
        assert!(
            observed
                .validate(&action, "https://api.github.com")
                .is_err()
        );
        observed.run_url = Some("https://api.github.com/repos/owner/app/actions/runs/23".into());
        observed.run_attempt = Some(2);
        assert!(
            observed
                .validate(&action, "https://api.github.com")
                .is_err()
        );
        observed.state = ReleaseObservationState::Ambiguous;
        observed.code = "external_rerun_observed".into();
        observed
            .validate(&action, "https://api.github.com")
            .unwrap();
    }
}
