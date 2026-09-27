//! Trusted startup binding. The policy author selects names and finite bounds;
//! only the sealed local configuration selects network/credential/key material.
use opaque_core::authority_policy::{self as policy, ActionApproval, CompiledPolicy};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub path: PathBuf,
    pub digest: String,
    pub name: String,
    pub namespace: String,
    pub tenant_ref: String,
    pub connector_ref: String,
    pub reviewer_ref: String,
    pub reviewer_id: String,
    pub reviewer_public_key: String,
    pub generation: u64,
    pub profile: crate::scope_runtime::connector::Profile,
}
impl Config {
    pub fn resolve(
        &self,
        tenant: &opaque_core::tenant::TenantBinding,
    ) -> Result<crate::scope_runtime::Config, String> {
        if !self.path.is_absolute() {
            return Err("authority policy requires an absolute manifest path".into());
        }
        let compiled = policy::read(&self.path)?;
        self.bind(&compiled, tenant)?;
        let authority = &compiled.policy.spec.authority;
        // The compiler admits exactly one kind-specific field per operation.
        let (allowed_statuses, workflows) = match (
            authority.operation.as_str(),
            &authority.allowed_statuses,
            &authority.workflows,
        ) {
            (policy::OPERATION, Some(statuses), None) => (
                statuses
                    .iter()
                    .map(|s| match s {
                        policy::Status::Open => crate::scope_runtime::connector::Status::Open,
                        policy::Status::Closed => crate::scope_runtime::connector::Status::Closed,
                        policy::Status::Resolved => {
                            crate::scope_runtime::connector::Status::Resolved
                        }
                    })
                    .collect(),
                None,
            ),
            (policy::DISPATCH_OPERATION, None, Some(targets)) => (vec![], Some(targets.clone())),
            _ => return Err("authority policy operation is not supported by this broker".into()),
        };
        Ok(crate::scope_runtime::Config {
            profile: self.profile.clone(),
            reviewer_id: self.reviewer_id.clone(),
            reviewer_public_key: self.reviewer_public_key.clone(),
            generation: self.generation,
            max_scope_seconds: policy::duration_seconds(&authority.max_duration)?,
            max_attempts: authority.max_attempts,
            max_resources: authority.max_resources,
            exact_action: compiled.policy.spec.approval.action == ActionApproval::EveryAction,
            allowed_statuses,
            workflows,
            authority_policy: Some(compiled),
        })
    }
    fn bind(
        &self,
        compiled: &CompiledPolicy,
        tenant: &opaque_core::tenant::TenantBinding,
    ) -> Result<(), String> {
        let identity = &compiled.identity;
        if compiled.digest != self.digest
            || identity.name != self.name
            || identity.namespace != self.namespace
            || identity.tenant_ref != self.tenant_ref
            || identity.tenant_ref != tenant.tenant_id.as_str()
            || identity.connector_ref != self.connector_ref
            || identity.reviewer_ref != self.reviewer_ref
        {
            return Err(
                "authority policy digest or trusted identity/reference binding mismatch".into(),
            );
        }
        Ok(())
    }
}
pub fn resolve(
    legacy: Option<crate::scope_runtime::Config>,
    selected: Option<&Config>,
    tenant: &opaque_core::tenant::TenantBinding,
) -> Result<Option<crate::scope_runtime::Config>, String> {
    match (legacy, selected) {
        (Some(_), Some(_)) => Err("scope_workflow and authority_policy cannot coexist".into()),
        (legacy, None) => Ok(legacy),
        (None, Some(config)) => config.resolve(tenant).map(Some),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
