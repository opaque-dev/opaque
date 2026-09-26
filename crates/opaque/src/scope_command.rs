use clap::Subcommand;
use serde_json::{Value, json};
use std::path::PathBuf;
#[derive(Debug, Subcommand)]
pub enum Action {
    /// Request a human-reviewed scope. JSON: resources, expires_in_secs, max_attempts,
    /// plus statuses for the support kind.
    Plan {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Materialize an approved issuance round; does not run work.
    Activate {
        round_id: String,
    },
    /// Prepare one exact action from broker-read provider state and request review.
    Prepare {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Execute an approved exact-action round once.
    Execute {
        #[arg(long)]
        round_id: String,
        #[arg(long)]
        issuance_round_id: String,
    },
    /// Execute within approved issuance only when startup policy explicitly permits it.
    Run {
        #[arg(long)]
        manifest: PathBuf,
    },
    Show {
        scope_id: String,
    },
    /// Read a charged request outcome; never dispatches or retries.
    Outcome {
        #[arg(long)]
        scope_id: String,
        #[arg(long)]
        request_id: String,
    },
    Revoke {
        scope_id: String,
    },
    /// Read a bounded historical projection; requires delegated auditor or admin role.
    Snapshot,
}
/// An `unknown` outcome is a charged attempt whose provider effect is not known.
/// Say so plainly for every scope result that carries a state; the GitHub
/// `workflow_dispatch` call has no idempotency key, so a resend could run twice.
pub fn unknown_outcome_note(method: &str, result: Option<&Value>) -> Option<String> {
    if !matches!(method, "scope_outcome" | "scope_execute" | "scope_run") {
        return None;
    }
    let result = result?;
    if result.get("state").and_then(Value::as_str) != Some("unknown") {
        return None;
    }
    let mut note = String::from(
        "state unknown: the attempt is charged and the provider may or may not have performed it; nothing was or will be resent.",
    );
    if result.pointer("/action/operation").and_then(Value::as_str)
        == Some("github.dispatch_staging_workflow")
    {
        note.push_str(
            " GitHub workflow_dispatch returns no run id and has no idempotency key, so a run may exist: inspect the repository's Actions runs before requesting a new dispatch.",
        );
    }
    Some(note)
}
pub fn params(action: Action) -> Result<(&'static str, Value), String> {
    use std::io::Read;
    fn manifest(path: PathBuf) -> Result<Value, String> {
        let file = std::fs::File::open(path).map_err(|_| "cannot open scope manifest")?;
        if !file
            .metadata()
            .map_err(|_| "cannot inspect scope manifest")?
            .is_file()
        {
            return Err("scope manifest must be a regular file".into());
        }
        let limit = opaque_core::MAX_FRAME_LENGTH - 8192;
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read scope manifest")?;
        if bytes.len() > limit {
            return Err("scope manifest exceeds request limit".into());
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid scope manifest JSON")?;
        if !value.is_object() {
            return Err("scope manifest must be an object".into());
        }
        Ok(value)
    }
    Ok(match action {
        Action::Plan { manifest: path } => ("scope_plan", manifest(path)?),
        Action::Activate { round_id } => ("scope_activate", json!({"round_id":round_id})),
        Action::Prepare { manifest: path } => ("scope_prepare", manifest(path)?),
        Action::Execute {
            round_id,
            issuance_round_id,
        } => (
            "scope_execute",
            json!({"round_id":round_id,"issuance_round_id":issuance_round_id}),
        ),
        Action::Run { manifest: path } => ("scope_run", manifest(path)?),
        Action::Show { scope_id } => ("scope_get", json!({"scope_id":scope_id})),
        Action::Outcome {
            scope_id,
            request_id,
        } => (
            "scope_outcome",
            json!({"scope_id":scope_id,"request_id":request_id}),
        ),
        Action::Revoke { scope_id } => ("scope_revoke", json!({"scope_id":scope_id})),
        Action::Snapshot => ("scope_snapshot", json!({})),
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct ScopeCli {
        #[command(subcommand)]
        action: Action,
    }

    #[test]
    fn scope_commands_preserve_exact_rpc_identifiers_and_required_arguments() {
        for (args, method, expected) in [
            (
                vec!["scope", "activate", "round-1"],
                "scope_activate",
                json!({"round_id":"round-1"}),
            ),
            (
                vec![
                    "scope",
                    "execute",
                    "--round-id",
                    "action-round",
                    "--issuance-round-id",
                    "issuance-round",
                ],
                "scope_execute",
                json!({"round_id":"action-round","issuance_round_id":"issuance-round"}),
            ),
            (
                vec!["scope", "show", "scope-1"],
                "scope_get",
                json!({"scope_id":"scope-1"}),
            ),
            (
                vec![
                    "scope",
                    "outcome",
                    "--scope-id",
                    "scope-1",
                    "--request-id",
                    "request-1",
                ],
                "scope_outcome",
                json!({"scope_id":"scope-1","request_id":"request-1"}),
            ),
            (
                vec!["scope", "revoke", "scope-1"],
                "scope_revoke",
                json!({"scope_id":"scope-1"}),
            ),
            (vec!["scope", "snapshot"], "scope_snapshot", json!({})),
        ] {
            let action = ScopeCli::try_parse_from(args).unwrap().action;
            assert_eq!(params(action).unwrap(), (method, expected));
        }
        for args in [
            vec!["scope", "execute", "--round-id", "action-round"],
            vec!["scope", "outcome", "--scope-id", "scope-1"],
            vec!["scope", "plan"],
            vec!["scope", "snapshot", "--approve"],
        ] {
            assert!(ScopeCli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn unknown_outcomes_are_stated_plainly_and_dispatch_names_the_missing_idempotency_key() {
        let dispatch =
            json!({"state":"unknown","action":{"operation":"github.dispatch_staging_workflow"}});
        let support = json!({"state":"unknown","action":{"operation":"support.case.set_status"}});
        for method in ["scope_outcome", "scope_execute", "scope_run"] {
            let note = unknown_outcome_note(method, Some(&dispatch)).unwrap();
            assert!(note.contains("may or may not have performed"));
            assert!(note.contains("no idempotency key"));
            assert!(note.contains("Actions runs"));
            let note = unknown_outcome_note(method, Some(&support)).unwrap();
            assert!(note.contains("may or may not have performed"));
            assert!(!note.contains("idempotency"));
        }
        assert!(
            unknown_outcome_note("scope_outcome", Some(&json!({"state":"api_accepted"}))).is_none()
        );
        assert!(
            unknown_outcome_note("scope_outcome", Some(&json!({"state":"rejected"}))).is_none()
        );
        assert!(unknown_outcome_note("scope_get", Some(&dispatch)).is_none());
        assert!(unknown_outcome_note("scope_outcome", None).is_none());
    }

    #[test]
    fn scope_manifest_commands_preserve_content_without_claiming_validation_or_approval() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("manifest.json");
        let value = json!({"resources":["case1"],"statuses":["closed"],"expires_in_secs":600,"max_attempts":1});
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        for (action, method) in [
            (
                Action::Plan {
                    manifest: path.clone(),
                },
                "scope_plan",
            ),
            (
                Action::Prepare {
                    manifest: path.clone(),
                },
                "scope_prepare",
            ),
            (
                Action::Run {
                    manifest: path.clone(),
                },
                "scope_run",
            ),
        ] {
            assert_eq!(params(action).unwrap(), (method, value.clone()));
        }
    }

    #[test]
    fn malformed_missing_nonobject_and_oversized_manifests_are_rejected_locally() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("manifest.json");
        assert_eq!(
            params(Action::Plan {
                manifest: path.clone()
            })
            .unwrap_err(),
            "cannot open scope manifest"
        );
        for bytes in [b"{".as_slice(), b"[]", b"null", b"\"literal\""] {
            std::fs::write(&path, bytes).unwrap();
            assert!(
                params(Action::Plan {
                    manifest: path.clone()
                })
                .is_err()
            );
        }
        assert_eq!(
            params(Action::Plan {
                manifest: directory.path().into()
            })
            .unwrap_err(),
            "scope manifest must be a regular file"
        );
        std::fs::write(&path, vec![b' '; opaque_core::MAX_FRAME_LENGTH - 8192 + 1]).unwrap();
        assert_eq!(
            params(Action::Plan { manifest: path }).unwrap_err(),
            "scope manifest exceeds request limit"
        );
    }
}
