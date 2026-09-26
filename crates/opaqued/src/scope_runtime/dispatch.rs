//! GitHub Actions `workflow_dispatch` adapter for the scope runtime. Trusted
//! configuration selects the API host, credential and the complete set of
//! dispatch targets; agent input can only name a target the approved scope
//! already carries. The protocol lives in `opaque_providers::github::workflow`,
//! next to the bounded staging task family that already brokers this call.
use super::connector::Profile;
use super::custody::{self, Contract};
use opaque_bounded_work::scope_store::Outcome;
use opaque_core::{authority_policy::WorkflowTarget, scope::FieldValue};
use opaque_providers::github::workflow::{self, Acknowledgment};

/// The broker operation name shared with the bounded staging task family.
pub const OPERATION: &str = opaque_core::release::STAGING_RELEASE_OPERATION;
/// The single written field: the `ref` in the dispatch body. Its value must
/// equal the ref component of the action's resource.
pub const FIELD: &str = "ref";
const CONTRACT: Contract = Contract {
    noun: "GitHub",
    contract: "opaque.github.workflow-dispatch.v1",
    profile_domain: "opaque.github-dispatch.provider-profile",
    credential_domain: "opaque.github-dispatch.credential.v1",
};

/// Broker-read state a reviewer sees before approving one dispatch. The head
/// commit is the action's resource version; GitHub does not enforce it as a
/// precondition, so the broker re-reads it immediately before the POST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub workflow_id: u64,
    pub workflow_state: String,
    pub head_sha: String,
    pub protected: bool,
}
impl Observation {
    pub fn fields(&self) -> Vec<FieldValue> {
        vec![
            FieldValue {
                field: "head_sha".into(),
                value: self.head_sha.clone(),
            },
            FieldValue {
                field: "branch_protected".into(),
                value: self.protected.to_string(),
            },
            FieldValue {
                field: "workflow_id".into(),
                value: self.workflow_id.to_string(),
            },
            FieldValue {
                field: "workflow_state".into(),
                value: self.workflow_state.clone(),
            },
        ]
    }
}

#[derive(Clone)]
pub struct Connector {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    authorization: reqwest::header::HeaderValue,
    pub digest: String,
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
    fn target<'a>(target: &'a WorkflowTarget) -> Result<workflow::Target<'a>, String> {
        target.validate()?;
        Ok(workflow::Target {
            repository: &target.repository,
            path: &target.path,
            git_ref: &target.git_ref,
        })
    }
    /// Three bounded reads: the workflow must be active at the named path, the
    /// branch must resolve to a head commit, and no tag may share its name.
    pub async fn read(&self, target: &WorkflowTarget) -> Result<Observation, String> {
        let target = Self::target(target)?;
        let workflow =
            workflow::read_workflow(&self.client, &self.endpoint, &target, &self.authorization)
                .await?;
        let branch =
            workflow::read_branch(&self.client, &self.endpoint, &target, &self.authorization)
                .await?;
        workflow::tag_absent(&self.client, &self.endpoint, &target, &self.authorization).await?;
        Ok(Observation {
            workflow_id: workflow.id,
            workflow_state: workflow.state,
            head_sha: branch.commit.sha,
            protected: branch.protected,
        })
    }
    /// Exactly one POST. A head that moved since review, or a head that cannot
    /// be re-read, is `Rejected`: nothing was sent. A 2xx acknowledgment is
    /// `ApiAccepted`, never completion. Everything else is `Unknown`, and
    /// `workflow_dispatch` has no idempotency key, so the run may or may not
    /// exist; the caller must never send again.
    pub async fn write(&self, target: &WorkflowTarget, head_sha: &str) -> Outcome {
        let Ok(target) = Self::target(target) else {
            return Outcome::Unknown;
        };
        match workflow::read_branch(&self.client, &self.endpoint, &target, &self.authorization)
            .await
        {
            Ok(branch) if branch.commit.sha == head_sha => {}
            _ => return Outcome::Rejected,
        }
        match workflow::dispatch(&self.client, &self.endpoint, &target, &self.authorization).await {
            Acknowledgment::Accepted => Outcome::ApiAccepted,
            Acknowledgment::Rejected => Outcome::Rejected,
            Acknowledgment::Unknown => Outcome::Unknown,
        }
    }
}
