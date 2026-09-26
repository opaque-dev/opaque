//! One typed staging dispatch. Policy, approval, reservation, and durable
//! at-most-once charging belong to the broker caller, never to this provider.

use base64::Engine;
use opaque_core::release::{
    ReleaseCorrelation, ReleaseObservation, ReleaseObservationState, StagingReleaseAction,
};
use opaque_core::task::{SlotOutcome, SlotState, TaskManifest};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::client::{DEFAULT_GITHUB_API_URL, GITHUB_API_URL_ENV};
use super::{DEFAULT_GITHUB_TOKEN_REF, GITHUB_TOKEN_REF_ENV};
use crate::internal_resolve::CompositeResolver;
use opaque_core::resolver::SecretResolver;

use super::workflow::{self, Acknowledgment};
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_WORKFLOW_BYTES: usize = 128 * 1024;
const MAX_RUN_PAGES: u32 = 3;

fn unavailable() -> String {
    "staging provider scope or evidence unavailable".into()
}

fn endpoint() -> Result<String, String> {
    let value = std::env::var(GITHUB_API_URL_ENV).unwrap_or_else(|_| DEFAULT_GITHUB_API_URL.into());
    let url = reqwest::Url::parse(&value).map_err(|_| unavailable())?;
    let explicit_loopback = std::env::var("OPAQUE_DOGFOOD_LOOPBACK").as_deref() == Ok("1")
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || url.scheme() == "http" && explicit_loopback)
    {
        return Err(unavailable());
    }
    Ok(url.as_str().trim_end_matches('/').into())
}

/// These values must be set in the trusted broker process by its operator.
/// A caller-supplied content hash does not establish a reviewed contract.
struct TrustedProfile {
    repo: String,
    path: String,
    branch: String,
    workflow_sha256: String,
    image: String,
}

impl TrustedProfile {
    fn load() -> Result<Self, String> {
        fn read(name: &str) -> Result<String, String> {
            std::env::var(name)
                .ok()
                .filter(|s| !s.is_empty())
                .ok_or_else(unavailable)
        }
        Ok(Self {
            repo: read("OPAQUE_STAGING_REPO")?,
            path: read("OPAQUE_STAGING_WORKFLOW_PATH")?,
            branch: read("OPAQUE_STAGING_REF")?,
            workflow_sha256: read("OPAQUE_STAGING_WORKFLOW_SHA256")?,
            image: read("OPAQUE_STAGING_IMAGE_REPOSITORY")?,
        })
    }

    fn matches(&self, action: &StagingReleaseAction) -> bool {
        self.repo == action.repo
            && self.path == action.workflow_path
            && self.branch == action.workflow_ref
            && self.workflow_sha256 == action.workflow_sha256
            && self.image == action.image_repository
            && action.environment == "staging"
    }
}

/// Fill trusted authority and explicit credential refs before policy checks.
/// Provisional identities and SHA are replaced by provider observations during
/// planning. This function performs no IO and does not resolve credentials.
pub fn prepare_staging_release(manifest: &mut TaskManifest) -> Result<(), String> {
    if !manifest.is_release() || manifest.actions.len() != 1 {
        return Err(unavailable());
    }
    manifest.github_api_url = endpoint()?;
    manifest.vault_api_url.clear();
    let profile = TrustedProfile::load()?;
    let action = manifest.actions[0]
        .as_release_mut()
        .ok_or_else(unavailable)?;
    if action.workflow_sha256.is_empty() {
        action.workflow_sha256 = profile.workflow_sha256.clone();
    }
    if !profile.matches(action) {
        return Err(unavailable());
    }
    action.repository_id = 1;
    action.workflow_id = 1;
    if action.approved_commit_sha.is_empty() {
        action.approved_commit_sha = "0".repeat(40);
    }
    if action.github_token_ref.is_none() {
        action.github_token_ref = Some(
            std::env::var(GITHUB_TOKEN_REF_ENV).unwrap_or_else(|_| DEFAULT_GITHUB_TOKEN_REF.into()),
        );
    }
    manifest.validate().map_err(|_| unavailable())
}

struct ReleaseClient {
    http: reqwest::Client,
    base: reqwest::Url,
}

impl ReleaseClient {
    fn new(base: &str) -> Result<Self, String> {
        Ok(Self {
            base: reqwest::Url::parse(base).map_err(|_| unavailable())?,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .no_proxy()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .map_err(|_| unavailable())?,
        })
    }

    fn url(&self, action: &StagingReleaseAction, suffix: &[&str]) -> Result<reqwest::Url, String> {
        workflow::repository_url(&self.base, &action.repo, suffix).map_err(|_| unavailable())
    }

    fn request(
        &self,
        method: reqwest::Method,
        url: reqwest::Url,
        token: &str,
    ) -> reqwest::RequestBuilder {
        workflow::headers(self.http.request(method, url).bearer_auth(token))
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        url: reqwest::Url,
        token: &str,
    ) -> Result<T, String> {
        let mut response = self
            .request(reqwest::Method::GET, url, token)
            .send()
            .await
            .map_err(|_| unavailable())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(unavailable());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(unavailable());
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| unavailable())
    }

    async fn repository(
        &self,
        action: &StagingReleaseAction,
        token: &str,
    ) -> Result<Repository, String> {
        let repository: Repository = self.get(self.url(action, &[])?, token).await?;
        if repository.id == 0 || !repository.full_name.eq_ignore_ascii_case(&action.repo) {
            return Err(unavailable());
        }
        Ok(repository)
    }

    async fn contract(
        &self,
        action: &StagingReleaseAction,
        token: &str,
        planning: bool,
    ) -> Result<(u64, String), String> {
        let workflow_key = if planning {
            action
                .workflow_path
                .rsplit('/')
                .next()
                .ok_or_else(unavailable)?
                .to_owned()
        } else {
            action.workflow_id.to_string()
        };
        let workflow: Workflow = self
            .get(
                self.url(action, &["actions", "workflows", &workflow_key])?,
                token,
            )
            .await?;
        if workflow.id == 0
            || workflow.path != action.workflow_path
            || workflow.state != "active"
            || !planning && workflow.id != action.workflow_id
        {
            return Err(unavailable());
        }
        let branch: Branch = self
            .get(
                self.url(action, &["branches", &action.workflow_ref])?,
                token,
            )
            .await?;
        if !branch.protected
            || branch.name != action.workflow_ref
            || !(planning && action.approved_commit_sha == "0".repeat(40))
                && branch.commit.sha != action.approved_commit_sha
        {
            return Err(unavailable());
        }
        // Dispatch accepts a branch OR tag name. Reject existing ambiguous
        // names instead of assuming the provider chooses the checked branch.
        let tag = self
            .request(
                reqwest::Method::GET,
                self.url(action, &["git", "ref", "tags", &action.workflow_ref])?,
                token,
            )
            .send()
            .await
            .map_err(|_| unavailable())?;
        if tag.status() != reqwest::StatusCode::NOT_FOUND {
            return Err(unavailable());
        }
        let mut content_url = self.url(
            action,
            &[
                "contents",
                ".github",
                "workflows",
                action
                    .workflow_path
                    .rsplit('/')
                    .next()
                    .ok_or_else(unavailable)?,
            ],
        )?;
        content_url
            .query_pairs_mut()
            .append_pair("ref", &branch.commit.sha);
        let content: Content = self.get(content_url, token).await?;
        if content.kind != "file"
            || content.path != action.workflow_path
            || content.encoding != "base64"
            || content.content.len() > MAX_WORKFLOW_BYTES * 2
        {
            return Err(unavailable());
        }
        let encoded: String = content
            .content
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| unavailable())?;
        if bytes.len() > MAX_WORKFLOW_BYTES
            || format!("{:x}", Sha256::digest(bytes)) != action.workflow_sha256
        {
            return Err(unavailable());
        }
        Ok((workflow.id, branch.commit.sha))
    }
}

#[derive(Deserialize)]
struct Repository {
    id: u64,
    full_name: String,
}
#[derive(Deserialize)]
struct Workflow {
    id: u64,
    path: String,
    state: String,
}
#[derive(Deserialize)]
struct Commit {
    sha: String,
}
#[derive(Deserialize)]
struct Branch {
    name: String,
    protected: bool,
    commit: Commit,
}
#[derive(Deserialize)]
struct Content {
    #[serde(rename = "type")]
    kind: String,
    path: String,
    encoding: String,
    content: String,
}

/// Bind exact repository/workflow identities and commit, after policy preflight.
pub async fn plan_staging_release(mut manifest: TaskManifest) -> Result<TaskManifest, String> {
    prepare_staging_release(&mut manifest)?;
    let client = ReleaseClient::new(&manifest.github_api_url)?;
    let action = manifest.actions[0]
        .as_release_mut()
        .ok_or_else(unavailable)?;
    let token = credential(action)?;
    let token_str = token.as_str().ok_or_else(unavailable)?;
    action.repository_id = client.repository(action, token_str).await?.id;
    let (workflow_id, commit) = client.contract(action, token_str, true).await?;
    action.workflow_id = workflow_id;
    action.approved_commit_sha = commit;
    manifest.validate().map_err(|_| unavailable())?;
    Ok(manifest)
}

fn credential(action: &StagingReleaseAction) -> Result<opaque_core::secret::SecretValue, String> {
    let token = CompositeResolver::new(crate::internal_resolve::default_secret_resolvers())
        .resolve(action.github_token_ref.as_deref().ok_or_else(unavailable)?)
        .map_err(|_| unavailable())?;
    token.mlock();
    if token.as_str().is_none() {
        return Err(unavailable());
    }
    Ok(token)
}

fn verify_manifest(manifest: &TaskManifest) -> Result<&StagingReleaseAction, String> {
    manifest.validate().map_err(|_| unavailable())?;
    if !manifest.is_release() || endpoint()? != manifest.github_api_url {
        return Err(unavailable());
    }
    let action = manifest.actions[0].as_release().ok_or_else(unavailable)?;
    if !TrustedProfile::load()?.matches(action) {
        return Err(unavailable());
    }
    Ok(action)
}

/// Exact correlation string required as the reviewed workflow's run-name.
pub fn staging_run_title(manifest: &TaskManifest, task_id: &str) -> Result<String, String> {
    let task = uuid::Uuid::parse_str(task_id).map_err(|_| unavailable())?;
    if task.to_string() != task_id {
        return Err(unavailable());
    }
    Ok(format!(
        "opaque-staging:{task_id}:{}",
        manifest.digest().map_err(|_| unavailable())?
    ))
}

fn outcome(state: SlotState, code: &str) -> SlotOutcome {
    SlotOutcome {
        ssh_receipt: None,
        inference_receipt: None,
        state,
        code: code.into(),
        provider_run_id: None,
    }
}

/// At most one POST per invocation, with no network retries. The caller must
/// durably consume its reserved slot at the final callback before POST. Once
/// that callback succeeds, revocation cannot cancel an in-flight dispatch.
pub async fn dispatch_staging_release<F, Fut>(
    manifest: &TaskManifest,
    action: &StagingReleaseAction,
    task_id: &str,
    before_dispatch: F,
) -> SlotOutcome
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), SlotOutcome>>,
{
    let rejected = || outcome(SlotState::Rejected, "source_unavailable");
    let Ok(bound) = verify_manifest(manifest) else {
        return rejected();
    };
    if bound != action || staging_run_title(manifest, task_id).is_err() {
        return rejected();
    }
    let Ok(client) = ReleaseClient::new(&manifest.github_api_url) else {
        return rejected();
    };
    let Ok(token) = credential(action) else {
        return rejected();
    };
    let Some(token_str) = token.as_str() else {
        return rejected();
    };
    let Ok(repository) = client.repository(action, token_str).await else {
        return rejected();
    };
    if repository.id != action.repository_id
        || client.contract(action, token_str, false).await.is_err()
    {
        return rejected();
    }
    let Ok(url) = client.url(
        action,
        &[
            "actions",
            "workflows",
            &action.workflow_id.to_string(),
            "dispatches",
        ],
    ) else {
        return rejected();
    };
    let Ok(digest) = manifest.digest() else {
        return rejected();
    };
    let request = client
        .request(reqwest::Method::POST, url, token_str)
        .json(&serde_json::json!({
            "ref": action.workflow_ref,
            "inputs": {
                "opaque_task_id": task_id,
                "opaque_manifest_digest": digest,
                "approved_commit_sha": action.approved_commit_sha,
                "image_repository": action.image_repository,
                "image_digest": action.image_digest,
                "environment": "staging"
            }
        }));
    if let Err(denial) = before_dispatch().await {
        return if denial.validate().is_ok() {
            denial
        } else {
            outcome(SlotState::Unknown, "internal_error")
        };
    }
    match request.send().await {
        Ok(response) if response.status().as_u16() == 204 => {
            outcome(SlotState::ApiAccepted, "api_accepted")
        }
        Ok(mut response) if response.status().as_u16() == 200 => {
            // Bind direct provider evidence where supported. Never follow its
            // supplied URLs, and never retry a malformed/partial response.
            let mut bytes = Vec::new();
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) if bytes.len() + chunk.len() <= 16384 => {
                        bytes.extend_from_slice(&chunk)
                    }
                    Ok(None) => break,
                    _ => return outcome(SlotState::Unknown, "transport_unknown"),
                }
            }
            #[derive(Deserialize)]
            struct DispatchResponse {
                workflow_run_id: u64,
            }
            let Ok(body) = serde_json::from_slice::<DispatchResponse>(&bytes) else {
                return outcome(SlotState::Unknown, "transport_unknown");
            };
            if body.workflow_run_id == 0 {
                return outcome(SlotState::Unknown, "transport_unknown");
            }
            SlotOutcome {
                ssh_receipt: None,
                inference_receipt: None,
                state: SlotState::ApiAccepted,
                code: "api_accepted".into(),
                provider_run_id: Some(body.workflow_run_id),
            }
        }
        other => match workflow::acknowledge(other) {
            Acknowledgment::Accepted => outcome(SlotState::ApiAccepted, "api_accepted"),
            Acknowledgment::Rejected => outcome(SlotState::Rejected, "provider_rejected"),
            Acknowledgment::Unknown => outcome(SlotState::Unknown, "transport_unknown"),
        },
    }
}

#[derive(Deserialize)]
struct Runs {
    total_count: u64,
    workflow_runs: Vec<Run>,
}
#[derive(Deserialize)]
struct Run {
    id: u64,
    workflow_id: u64,
    repository: Repository,
    head_repository: Repository,
    head_sha: String,
    head_branch: String,
    event: String,
    display_title: String,
    status: String,
    conclusion: Option<String>,
    run_attempt: u64,
}

fn observation(state: ReleaseObservationState, code: &str) -> ReleaseObservation {
    ReleaseObservation {
        state,
        correlation: ReleaseCorrelation::TaskTitle,
        code: code.into(),
        run_id: None,
        run_url: None,
        observed_commit_sha: None,
        checked_at: chrono::Utc::now().timestamp(),
        run_attempt: None,
    }
}

/// Read-only reconciliation. No dispatch/retry/cancel/rerun endpoint is called.
/// Correlation is bounded and exact; missing evidence is never proof of no run.
pub async fn reconcile_staging_release(
    manifest: &TaskManifest,
    task_id: &str,
    known_run_id: Option<u64>,
) -> Result<ReleaseObservation, String> {
    let action = verify_manifest(manifest)?;
    let title = staging_run_title(manifest, task_id)?;
    let client = ReleaseClient::new(&manifest.github_api_url)?;
    let token = credential(action)?;
    let token_str = token.as_str().ok_or_else(unavailable)?;
    if client.repository(action, token_str).await?.id != action.repository_id {
        return Err(unavailable());
    }
    if let Some(id) = known_run_id {
        if id == 0 {
            return Err(unavailable());
        }
        let run: Run = client
            .get(
                client.url(action, &["actions", "runs", &id.to_string()])?,
                token_str,
            )
            .await?;
        let mut observed = if run.id != id || !run_matches(&run, action, &title) {
            observation(ReleaseObservationState::Ambiguous, "run_evidence_mismatch")
        } else {
            observe_run(run, action, &client)?
        };
        observed.correlation = ReleaseCorrelation::DispatchResponse;
        observed.validate(action, &manifest.github_api_url)?;
        return Ok(observed);
    }
    let mut matches = Vec::new();
    let mut complete = false;
    let mut seen = std::collections::HashSet::new();
    let mut expected_count = None;
    for page in 1..=MAX_RUN_PAGES {
        let mut url = client.url(
            action,
            &[
                "actions",
                "workflows",
                &action.workflow_id.to_string(),
                "runs",
            ],
        )?;
        url.query_pairs_mut()
            .append_pair("event", "workflow_dispatch")
            .append_pair("branch", &action.workflow_ref)
            .append_pair("head_sha", &action.approved_commit_sha)
            .append_pair("per_page", "100")
            .append_pair("page", &page.to_string());
        let runs: Runs = client.get(url, token_str).await?;
        if runs.total_count > u64::from(MAX_RUN_PAGES) * 100 || runs.workflow_runs.len() > 100 {
            return Ok(observation(
                ReleaseObservationState::Ambiguous,
                "run_correlation_ambiguous",
            ));
        }
        if expected_count.is_some_and(|count| count != runs.total_count) {
            return Ok(observation(
                ReleaseObservationState::Ambiguous,
                "run_correlation_ambiguous",
            ));
        }
        expected_count = Some(runs.total_count);
        let count = runs.workflow_runs.len();
        for run in runs.workflow_runs {
            if !seen.insert(run.id) {
                return Ok(observation(
                    ReleaseObservationState::Ambiguous,
                    "run_correlation_ambiguous",
                ));
            }
            if run.display_title != title {
                continue;
            }
            if !run_matches(&run, action, &title) {
                return Ok(observation(
                    ReleaseObservationState::Ambiguous,
                    "run_evidence_mismatch",
                ));
            }
            matches.push(run);
        }
        if seen.len() as u64 == runs.total_count {
            complete = true;
            break;
        }
        if count < 100 {
            break;
        }
    }
    if !complete || matches.len() > 1 {
        return Ok(observation(
            ReleaseObservationState::Ambiguous,
            "run_correlation_ambiguous",
        ));
    }
    let Some(run) = matches.pop() else {
        return Ok(observation(
            ReleaseObservationState::Pending,
            "run_not_observed",
        ));
    };
    let result = observe_run(run, action, &client)?;
    result.validate(action, &manifest.github_api_url)?;
    Ok(result)
}

fn run_matches(run: &Run, action: &StagingReleaseAction, title: &str) -> bool {
    run.id > 0
        && run.workflow_id == action.workflow_id
        && run.repository.id == action.repository_id
        && run.repository.full_name.eq_ignore_ascii_case(&action.repo)
        && run.head_repository.id == action.repository_id
        && run
            .head_repository
            .full_name
            .eq_ignore_ascii_case(&action.repo)
        && run.head_sha == action.approved_commit_sha
        && run.head_branch == action.workflow_ref
        && run.event == "workflow_dispatch"
        && run.run_attempt > 0
        && run.display_title == title
}

fn observe_run(
    run: Run,
    action: &StagingReleaseAction,
    client: &ReleaseClient,
) -> Result<ReleaseObservation, String> {
    let (state, code) = if run.run_attempt > 1 {
        (
            ReleaseObservationState::Ambiguous,
            "external_rerun_observed",
        )
    } else {
        match (run.status.as_str(), run.conclusion.as_deref()) {
            ("completed", Some("success")) => {
                (ReleaseObservationState::Succeeded, "workflow_succeeded")
            }
            (
                "completed",
                Some(
                    "failure" | "cancelled" | "timed_out" | "action_required" | "neutral"
                    | "skipped" | "stale",
                ),
            ) => (ReleaseObservationState::Failed, "workflow_failed"),
            ("queued" | "in_progress" | "requested" | "waiting" | "pending", None) => {
                (ReleaseObservationState::Running, "run_in_progress")
            }
            _ => {
                return Ok(observation(
                    ReleaseObservationState::Ambiguous,
                    "run_evidence_mismatch",
                ));
            }
        }
    };
    let mut result = observation(state, code);
    result.run_id = Some(run.id);
    result.run_url = Some(
        client
            .url(action, &["actions", "runs", &run.id.to_string()])?
            .into(),
    );
    result.observed_commit_sha = Some(run.head_sha);
    result.run_attempt = Some(run.run_attempt);
    Ok(result)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::github::workflow::API_VERSION;
    use opaque_core::release::STAGING_RELEASE_OPERATION;
    use opaque_core::task::TaskAction;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TASK_ID: &str = "00000000-0000-4000-8000-000000000001";
    const WORKFLOW: &str = "reviewed fixture workflow bytes, no live deployment";
    const REPO: &str = "owner/app";
    const WORKFLOW_PATH: &str = ".github/workflows/opaque-staging.yml";

    struct EnvRestore(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl EnvRestore {
        fn configure(server: &MockServer) -> Self {
            let values = [
                (GITHUB_API_URL_ENV, server.uri()),
                (GITHUB_TOKEN_REF_ENV, "env:OPAQUE_TEST_RELEASE_PAT".into()),
                ("OPAQUE_TEST_RELEASE_PAT", "disposable-release-pat".into()),
                ("OPAQUE_DOGFOOD_LOOPBACK", "1".into()),
                ("OPAQUE_STAGING_REPO", REPO.into()),
                ("OPAQUE_STAGING_WORKFLOW_PATH", WORKFLOW_PATH.into()),
                ("OPAQUE_STAGING_REF", "main".into()),
                (
                    "OPAQUE_STAGING_IMAGE_REPOSITORY",
                    "ghcr.io/owner/app".into(),
                ),
                (
                    "OPAQUE_STAGING_WORKFLOW_SHA256",
                    format!("{:x}", Sha256::digest(WORKFLOW)),
                ),
            ];
            let mut saved = Vec::new();
            for (name, value) in values {
                saved.push((name, std::env::var_os(name)));
                // Serialized across GitHub module environment-mutating tests.
                unsafe {
                    std::env::set_var(name, value);
                }
            }
            Self(saved)
        }
    }
    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (name, previous) in self.0.drain(..).rev() {
                unsafe {
                    match previous {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }
    }

    fn manifest() -> TaskManifest {
        TaskManifest {
            schema_version: 2,
            title: "Dogfood staging release".into(),
            expires_in_secs: 600,
            github_api_url: String::new(),
            vault_api_url: String::new(),
            actions: vec![TaskAction::StagingRelease(StagingReleaseAction {
                operation: STAGING_RELEASE_OPERATION.into(),
                repo: REPO.into(),
                repository_id: 0,
                workflow_path: WORKFLOW_PATH.into(),
                workflow_id: 0,
                workflow_ref: "main".into(),
                approved_commit_sha: String::new(),
                workflow_sha256: String::new(),
                image_repository: "ghcr.io/owner/app".into(),
                image_digest: format!("sha256:{}", "c".repeat(64)),
                environment: "staging".into(),
                github_token_ref: None,
            })],
        }
    }

    async fn scope(
        server: &MockServer,
        repo_id: u64,
        sha: &str,
        protected: bool,
        bytes: &str,
        delay: u64,
    ) {
        Mock::given(method("GET"))
            .and(path("/repos/owner/app"))
            .and(header("authorization", "Bearer disposable-release-pat"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id":repo_id,"full_name":REPO})),
            )
            .mount(server)
            .await;
        for key in ["opaque-staging.yml", "71"] {
            Mock::given(method("GET"))
                .and(path(format!("/repos/owner/app/actions/workflows/{key}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"id":71,"path":WORKFLOW_PATH,"state":"active"}),
                ))
                .mount(server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/repos/owner/app/branches/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"name":"main","protected":protected,"commit":{"sha":sha}}),
            ))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/owner/app/git/ref/tags/main"))
            .respond_with(ResponseTemplate::new(404))
            .mount(server)
            .await;
        Mock::given(method("GET")).and(path(format!("/repos/owner/app/contents/{WORKFLOW_PATH}")))
            .and(query_param("ref", sha))
            .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(delay)).set_body_json(serde_json::json!({
                "type":"file", "path":WORKFLOW_PATH, "encoding":"base64", "content":base64::engine::general_purpose::STANDARD.encode(bytes)
            }))).mount(server).await;
    }

    fn run(manifest: &TaskManifest, id: u64) -> serde_json::Value {
        serde_json::json!({
            "id":id,"workflow_id":71,"repository":{"id":42,"full_name":REPO},
            "head_repository":{"id":42,"full_name":REPO}, "head_sha":"a".repeat(40),
            "head_branch":"main", "event":"workflow_dispatch", "display_title":staging_run_title(manifest,TASK_ID).unwrap(),
            "status":"completed", "conclusion":"success", "run_attempt":1,
            "html_url":"https://attacker.invalid/secret", "url":"https://attacker.invalid/secret"
        })
    }

    async fn runs(server: &MockServer, values: Vec<serde_json::Value>) {
        Mock::given(method("GET"))
            .and(path("/repos/owner/app/actions/workflows/71/runs"))
            .and(query_param("event", "workflow_dispatch"))
            .and(query_param("branch", "main"))
            .and(query_param("head_sha", "a".repeat(40)))
            .and(query_param("per_page", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"total_count":values.len(),"workflow_runs":values}),
            ))
            .mount(server)
            .await;
    }

    async fn post_count(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count()
    }

    #[tokio::test]
    async fn plans_fixed_authority_dispatches_once_and_reconciles_without_writing() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        let server = MockServer::start().await;
        let _env = EnvRestore::configure(&server);
        scope(&server, 42, &"a".repeat(40), true, WORKFLOW, 0).await;
        let planned = plan_staging_release(manifest()).await.unwrap();
        let action = planned.actions[0].as_release().unwrap();
        assert_eq!(action.repository_id, 42);
        assert_eq!(action.workflow_id, 71);
        assert_eq!(action.approved_commit_sha, "a".repeat(40));
        Mock::given(method("POST"))
            .and(path("/repos/owner/app/actions/workflows/71/dispatches"))
            .and(header("x-github-api-version", API_VERSION))
            .and(body_json(serde_json::json!({"ref":"main","inputs":{
                "opaque_task_id":TASK_ID,"opaque_manifest_digest":planned.digest().unwrap(),
                "approved_commit_sha":"a".repeat(40),"image_repository":"ghcr.io/owner/app",
                "image_digest":format!("sha256:{}","c".repeat(64)),"environment":"staging"
            }})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"workflow_run_id":123})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let result = dispatch_staging_release(&planned, action, TASK_ID, || async { Ok(()) }).await;
        assert_eq!(result.state, SlotState::ApiAccepted);
        assert_eq!(result.provider_run_id, Some(123));
        runs(&server, vec![run(&planned, 123)]).await;
        let observed = reconcile_staging_release(&planned, TASK_ID, None)
            .await
            .unwrap();
        assert_eq!(observed.state, ReleaseObservationState::Succeeded);
        assert_eq!(
            observed.run_url,
            Some(format!("{}/repos/owner/app/actions/runs/123", server.uri()))
        );
        assert_eq!(post_count(&server).await, 1);
    }

    #[tokio::test]
    async fn trusted_profile_and_full_validation_precede_provider_io() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        let server = MockServer::start().await;
        let _env = EnvRestore::configure(&server);
        let mut bad = manifest();
        bad.actions[0].as_release_mut().unwrap().workflow_sha256 = "d".repeat(64);
        assert!(plan_staging_release(bad).await.is_err());
        let mut bad = manifest();
        bad.actions[0].as_release_mut().unwrap().environment = "production".into();
        assert!(plan_staging_release(bad).await.is_err());
        let mut prepared = manifest();
        prepare_staging_release(&mut prepared).unwrap();
        assert_eq!(
            prepared.actions[0]
                .as_release()
                .unwrap()
                .github_token_ref
                .as_deref(),
            Some("env:OPAQUE_TEST_RELEASE_PAT")
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn changed_identity_commit_protection_or_workflow_never_dispatches() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        for (repo_id, sha, protected, bytes) in [
            (43, "a".repeat(40), true, WORKFLOW),
            (42, "b".repeat(40), true, WORKFLOW),
            (42, "a".repeat(40), false, WORKFLOW),
            (42, "a".repeat(40), true, "changed workflow bytes"),
        ] {
            let server = MockServer::start().await;
            let _env = EnvRestore::configure(&server);
            scope(&server, 42, &"a".repeat(40), true, WORKFLOW, 0).await;
            let planned = plan_staging_release(manifest()).await.unwrap();
            server.reset().await;
            scope(&server, repo_id, &sha, protected, bytes, 0).await;
            let result = dispatch_staging_release(
                &planned,
                planned.actions[0].as_release().unwrap(),
                TASK_ID,
                || async { panic!("changed authority must not reach dispatch fence") },
            )
            .await;
            assert_eq!(result.code, "source_unavailable");
            assert_eq!(post_count(&server).await, 0);
        }
    }

    #[tokio::test]
    async fn callback_denial_after_delayed_preparation_prevents_post() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        let server = MockServer::start().await;
        let _env = EnvRestore::configure(&server);
        scope(&server, 42, &"a".repeat(40), true, WORKFLOW, 30).await;
        let planned = plan_staging_release(manifest()).await.unwrap();
        let result = dispatch_staging_release(
            &planned,
            planned.actions[0].as_release().unwrap(),
            TASK_ID,
            || async { Err(outcome(SlotState::Rejected, "revoked")) },
        )
        .await;
        assert_eq!(result.code, "revoked");
        assert_eq!(post_count(&server).await, 0);
    }

    #[tokio::test]
    async fn dispatch_unknown_rejection_and_legacy_acceptance_are_not_retried() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        for (status, expected) in [
            (200, SlotState::Unknown),
            (500, SlotState::Unknown),
            (408, SlotState::Unknown),
            (302, SlotState::Unknown),
            (422, SlotState::Rejected),
            (204, SlotState::ApiAccepted),
        ] {
            let server = MockServer::start().await;
            let _env = EnvRestore::configure(&server);
            scope(&server, 42, &"a".repeat(40), true, WORKFLOW, 0).await;
            let planned = plan_staging_release(manifest()).await.unwrap();
            Mock::given(method("POST"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("Location", format!("{}/trap", server.uri())),
                )
                .expect(1)
                .mount(&server)
                .await;
            let result = dispatch_staging_release(
                &planned,
                planned.actions[0].as_release().unwrap(),
                TASK_ID,
                || async { Ok(()) },
            )
            .await;
            assert_eq!(result.state, expected);
            runs(&server, vec![]).await;
            assert_eq!(
                reconcile_staging_release(&planned, TASK_ID, None)
                    .await
                    .unwrap()
                    .state,
                ReleaseObservationState::Pending
            );
            assert_eq!(post_count(&server).await, 1);
            assert!(
                !server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .any(|r| r.url.path() == "/trap")
            );
        }
    }

    #[tokio::test]
    async fn exact_correlation_rejects_changed_scope_duplicate_runs_and_external_reruns() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        for case in 0..7 {
            let server = MockServer::start().await;
            let _env = EnvRestore::configure(&server);
            scope(&server, 42, &"a".repeat(40), true, WORKFLOW, 0).await;
            let planned = plan_staging_release(manifest()).await.unwrap();
            let mut value = run(&planned, 123);
            let expected = match case {
                0 => {
                    value["head_sha"] = serde_json::json!("b".repeat(40));
                    "run_evidence_mismatch"
                }
                1 => {
                    value["repository"]["id"] = serde_json::json!(99);
                    "run_evidence_mismatch"
                }
                2 => {
                    value["workflow_id"] = serde_json::json!(99);
                    "run_evidence_mismatch"
                }
                3 => {
                    value["display_title"] = serde_json::json!("some other task");
                    "run_not_observed"
                }
                4 => {
                    value["run_attempt"] = serde_json::json!(2);
                    "external_rerun_observed"
                }
                5 => "run_correlation_ambiguous",
                _ => {
                    value["conclusion"] = serde_json::json!("raw provider payload");
                    "run_evidence_mismatch"
                }
            };
            let mut values = vec![value];
            if case == 5 {
                values.push(run(&planned, 124));
            }
            runs(&server, values).await;
            let observed = reconcile_staging_release(&planned, TASK_ID, None)
                .await
                .unwrap();
            assert_eq!(observed.code, expected);
            observed
                .validate(
                    planned.actions[0].as_release().unwrap(),
                    &planned.github_api_url,
                )
                .unwrap();
            assert_eq!(post_count(&server).await, 0);
        }
    }

    #[tokio::test]
    async fn direct_dispatch_id_is_stronger_evidence_and_never_falls_back_to_title_search() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        for wrong_scope in [false, true] {
            let server = MockServer::start().await;
            let _env = EnvRestore::configure(&server);
            scope(&server, 42, &"a".repeat(40), true, WORKFLOW, 0).await;
            let planned = plan_staging_release(manifest()).await.unwrap();
            let mut evidence = run(&planned, 123);
            if wrong_scope {
                evidence["workflow_id"] = serde_json::json!(999);
            }
            Mock::given(method("GET"))
                .and(path("/repos/owner/app/actions/runs/123"))
                .respond_with(ResponseTemplate::new(200).set_body_json(evidence))
                .expect(1)
                .mount(&server)
                .await;
            let observed = reconcile_staging_release(&planned, TASK_ID, Some(123))
                .await
                .unwrap();
            assert_eq!(observed.correlation, ReleaseCorrelation::DispatchResponse);
            assert_eq!(
                observed.state,
                if wrong_scope {
                    ReleaseObservationState::Ambiguous
                } else {
                    ReleaseObservationState::Succeeded
                }
            );
            assert!(
                !server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .any(|r| r.url.path().ends_with("/71/runs"))
            );
            assert_eq!(post_count(&server).await, 0);
        }
    }

    #[tokio::test]
    async fn same_name_tag_and_incomplete_run_search_fail_closed() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        let server = MockServer::start().await;
        let _env = EnvRestore::configure(&server);
        scope(&server, 42, &"a".repeat(40), true, WORKFLOW, 0).await;
        let planned = plan_staging_release(manifest()).await.unwrap();
        Mock::given(method("GET"))
            .and(path("/repos/owner/app/git/ref/tags/main"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"ref":"refs/tags/main"})),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        let result = dispatch_staging_release(
            &planned,
            planned.actions[0].as_release().unwrap(),
            TASK_ID,
            || async { panic!("same-name tag must not reach the dispatch fence") },
        )
        .await;
        assert_eq!(result.code, "source_unavailable");
        Mock::given(method("GET"))
            .and(path("/repos/owner/app/actions/workflows/71/runs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 2, "workflow_runs": [run(&planned, 123)]
            })))
            .mount(&server)
            .await;
        let observed = reconcile_staging_release(&planned, TASK_ID, None)
            .await
            .unwrap();
        assert_eq!(observed.code, "run_correlation_ambiguous");
        assert_eq!(post_count(&server).await, 0);
    }

    #[tokio::test]
    async fn preparation_rejects_each_untrusted_profile_or_endpoint_component_without_io() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        let server = MockServer::start().await;
        let _env = EnvRestore::configure(&server);
        for endpoint_value in [
            "file:///private",
            "https://user@api.github.com",
            "https://:password@api.github.com",
            "https://api.github.com?query=1",
            "https://api.github.com#fragment",
            "http://api.github.com",
        ] {
            unsafe {
                std::env::set_var(GITHUB_API_URL_ENV, endpoint_value);
            }
            assert_eq!(
                prepare_staging_release(&mut manifest()).unwrap_err(),
                unavailable()
            );
        }
        unsafe {
            std::env::set_var(GITHUB_API_URL_ENV, server.uri());
        }
        for field in 0..6 {
            let mut candidate = manifest();
            let action = candidate.actions[0].as_release_mut().unwrap();
            match field {
                0 => action.repo = "owner/foreign".into(),
                1 => action.workflow_path = ".github/workflows/foreign.yml".into(),
                2 => action.workflow_ref = "other".into(),
                3 => action.workflow_sha256 = "d".repeat(64),
                4 => action.image_repository = "ghcr.io/other/app".into(),
                _ => action.environment = "production".into(),
            }
            assert_eq!(
                prepare_staging_release(&mut candidate).unwrap_err(),
                unavailable()
            );
        }
        for name in [
            "OPAQUE_STAGING_REPO",
            "OPAQUE_STAGING_WORKFLOW_PATH",
            "OPAQUE_STAGING_REF",
            "OPAQUE_STAGING_WORKFLOW_SHA256",
            "OPAQUE_STAGING_IMAGE_REPOSITORY",
        ] {
            let saved = std::env::var(name).unwrap();
            unsafe {
                std::env::set_var(name, "");
            }
            assert_eq!(
                prepare_staging_release(&mut manifest()).unwrap_err(),
                unavailable()
            );
            unsafe {
                std::env::set_var(name, saved);
            }
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn workflow_and_content_response_mutations_never_reach_dispatch_authority() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        for field in 0..12 {
            let server = MockServer::start().await;
            let _env = EnvRestore::configure(&server);
            scope(&server, 42, &"a".repeat(40), true, WORKFLOW, 0).await;
            let planned = plan_staging_release(manifest()).await.unwrap();
            server.reset().await;
            scope(&server, 42, &"a".repeat(40), true, WORKFLOW, 0).await;
            let (route, body) = match field {
                0 => (
                    "/repos/owner/app".to_owned(),
                    serde_json::json!({"id":0,"full_name":REPO}),
                ),
                1 => (
                    "/repos/owner/app".to_owned(),
                    serde_json::json!({"id":42,"full_name":"owner/foreign"}),
                ),
                2..=5 => {
                    let mut value =
                        serde_json::json!({"id":71,"path":WORKFLOW_PATH,"state":"active"});
                    match field {
                        2 => value["id"] = 0.into(),
                        3 => value["path"] = ".github/workflows/foreign.yml".into(),
                        4 => value["state"] = "disabled_manually".into(),
                        _ => value["id"] = 72.into(),
                    };
                    ("/repos/owner/app/actions/workflows/71".into(), value)
                }
                6 => (
                    "/repos/owner/app/branches/main".into(),
                    serde_json::json!({"name":"foreign","protected":true,"commit":{"sha":"a".repeat(40)}}),
                ),
                _ => {
                    let mut value = serde_json::json!({"type":"file","path":WORKFLOW_PATH,"encoding":"base64","content":base64::engine::general_purpose::STANDARD.encode(WORKFLOW)});
                    match field {
                        7 => value["type"] = "symlink".into(),
                        8 => value["path"] = ".github/workflows/foreign.yml".into(),
                        9 => value["encoding"] = "utf-8".into(),
                        10 => value["content"] = "A".repeat(MAX_WORKFLOW_BYTES * 2 + 1).into(),
                        _ => {
                            value["content"] = base64::engine::general_purpose::STANDARD
                                .encode(vec![0; MAX_WORKFLOW_BYTES + 1])
                                .into()
                        }
                    };
                    (format!("/repos/owner/app/contents/{WORKFLOW_PATH}"), value)
                }
            };
            Mock::given(method("GET"))
                .and(path(route))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .with_priority(1)
                .expect(1)
                .mount(&server)
                .await;
            let result = dispatch_staging_release(
                &planned,
                planned.actions[0].as_release().unwrap(),
                TASK_ID,
                || async { panic!("invalid observed contract reached reservation fence") },
            )
            .await;
            assert_eq!(result.state, SlotState::Rejected);
            assert_eq!(result.code, "source_unavailable");
            assert_eq!(post_count(&server).await, 0);
        }
    }

    #[tokio::test]
    async fn dispatch_acknowledgment_bounds_preserve_unknown_and_one_post() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        for (body, expected, id) in [
            (
                serde_json::json!({"workflow_run_id":0}).to_string(),
                SlotState::Unknown,
                None,
            ),
            (" ".repeat(16385), SlotState::Unknown, None),
            (
                serde_json::json!({"workflow_run_id":123,"url":"https://foreign.invalid"})
                    .to_string(),
                SlotState::ApiAccepted,
                Some(123),
            ),
        ] {
            let server = MockServer::start().await;
            let _env = EnvRestore::configure(&server);
            scope(&server, 42, &"a".repeat(40), true, WORKFLOW, 0).await;
            let planned = plan_staging_release(manifest()).await.unwrap();
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .expect(1)
                .mount(&server)
                .await;
            let charged = std::cell::Cell::new(0);
            let result = dispatch_staging_release(
                &planned,
                planned.actions[0].as_release().unwrap(),
                TASK_ID,
                || async {
                    charged.set(charged.get() + 1);
                    Ok(())
                },
            )
            .await;
            assert_eq!(charged.get(), 1);
            assert_eq!(result.state, expected);
            assert_eq!(result.provider_run_id, id);
            assert_eq!(post_count(&server).await, 1);
            assert_eq!(
                result.code,
                if id.is_some() {
                    "api_accepted"
                } else {
                    "transport_unknown"
                }
            );
            result.validate().unwrap();
        }
    }

    #[tokio::test]
    async fn invalid_dispatch_binding_and_invalid_fence_result_never_post() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        let server = MockServer::start().await;
        let _env = EnvRestore::configure(&server);
        scope(&server, 42, &"a".repeat(40), true, WORKFLOW, 0).await;
        let planned = plan_staging_release(manifest()).await.unwrap();
        let mut foreign = planned.actions[0].as_release().unwrap().clone();
        foreign.workflow_id += 1;
        for (action, id) in [
            (&foreign, TASK_ID),
            (planned.actions[0].as_release().unwrap(), "invalid-task-id"),
        ] {
            let result = dispatch_staging_release(&planned, action, id, || async {
                panic!("invalid binding reached reservation")
            })
            .await;
            assert_eq!(result.code, "source_unavailable");
        }
        let result = dispatch_staging_release(
            &planned,
            planned.actions[0].as_release().unwrap(),
            TASK_ID,
            || async { Err(outcome(SlotState::Rejected, "not_a_valid_reason")) },
        )
        .await;
        assert_eq!(result.state, SlotState::Unknown);
        assert_eq!(result.code, "internal_error");
        assert_eq!(post_count(&server).await, 0);
    }

    #[tokio::test]
    async fn direct_run_identity_requires_every_immutable_scope_component() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        for field in 0..8 {
            let server = MockServer::start().await;
            let _env = EnvRestore::configure(&server);
            scope(&server, 42, &"a".repeat(40), true, WORKFLOW, 0).await;
            let planned = plan_staging_release(manifest()).await.unwrap();
            let mut evidence = run(&planned, 123);
            match field {
                0 => evidence["id"] = 0.into(),
                1 => evidence["repository"]["full_name"] = "owner/foreign".into(),
                2 => evidence["head_repository"]["id"] = 99.into(),
                3 => evidence["head_repository"]["full_name"] = "owner/foreign".into(),
                4 => evidence["head_branch"] = "foreign".into(),
                5 => evidence["event"] = "push".into(),
                6 => evidence["run_attempt"] = 0.into(),
                _ => evidence["display_title"] = "foreign-task".into(),
            }
            assert!(!run_matches(
                &serde_json::from_value(evidence.clone()).unwrap(),
                planned.actions[0].as_release().unwrap(),
                &staging_run_title(&planned, TASK_ID).unwrap()
            ));
            Mock::given(method("GET"))
                .and(path("/repos/owner/app/actions/runs/123"))
                .respond_with(ResponseTemplate::new(200).set_body_json(evidence))
                .expect(1)
                .mount(&server)
                .await;
            let observed = reconcile_staging_release(&planned, TASK_ID, Some(123))
                .await
                .unwrap();
            assert_eq!(observed.state, ReleaseObservationState::Ambiguous);
            assert_eq!(observed.code, "run_evidence_mismatch");
            assert_eq!(observed.correlation, ReleaseCorrelation::DispatchResponse);
            assert_eq!(post_count(&server).await, 0);
            assert!(
                !server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .any(|r| r.url.path().ends_with("/71/runs"))
            );
        }
    }

    #[tokio::test]
    async fn changing_pagination_and_duplicate_run_ids_are_ambiguous_not_absent() {
        let _lock = super::super::TEST_ENV_LOCK.lock().await;
        for mode in 0..4 {
            let server = MockServer::start().await;
            let _env = EnvRestore::configure(&server);
            scope(&server, 42, &"a".repeat(40), true, WORKFLOW, 0).await;
            let planned = plan_staging_release(manifest()).await.unwrap();
            let first: Vec<_> = (1..=if mode == 1 { 101 } else { 100 })
                .map(|id| {
                    let mut value = run(&planned, id);
                    value["display_title"] = "different task".into();
                    value
                })
                .collect();
            Mock::given(method("GET")).and(path("/repos/owner/app/actions/workflows/71/runs")).and(query_param("page","1")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"total_count":if mode==0 {301}else{101},"workflow_runs":first}))).expect(1).mount(&server).await;
            if mode >= 2 {
                Mock::given(method("GET")).and(path("/repos/owner/app/actions/workflows/71/runs")).and(query_param("page","2")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"total_count":if mode==2 {102}else{101},"workflow_runs":[run(&planned,1)]}))).expect(1).mount(&server).await;
            }
            let result = reconcile_staging_release(&planned, TASK_ID, None)
                .await
                .unwrap();
            assert_eq!(result.state, ReleaseObservationState::Ambiguous);
            assert_eq!(result.code, "run_correlation_ambiguous");
            assert_eq!(post_count(&server).await, 0);
        }
    }
}
