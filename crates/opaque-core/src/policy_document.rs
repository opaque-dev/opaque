//! The policy view of a complete broker TOML configuration. Unknown top-level
//! settings remain available to their owning subsystem and are ignored here.
use crate::policy::{
    ApprovalConfig, ClientMatch, IdentityMatch, PolicyRule, SecretNameMatch, TargetMatch,
    WorkspaceMatch,
};
use serde::{Deserialize, Serialize};

/// A key inside a `[[rules]]` table, or one of its sub-tables, that no policy
/// field reads. serde ignores it, so whatever it was meant to configure is
/// silently inert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownRuleKey {
    /// Zero-based index of the rule in the `rules` array.
    pub rule_index: usize,
    /// The rule's `name`, when it has one.
    pub rule_name: Option<String>,
    /// Table the key sits in: `rules`, `rules.approval`, `rules.workspace`, ...
    pub table: &'static str,
    /// The key nothing reads.
    pub key: String,
    /// Keys that table does accept.
    pub known: &'static [&'static str],
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PolicyDocument {
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub require_seal: bool,
}

impl PolicyDocument {
    pub fn from_toml(input: &str) -> Result<Self, toml_edit::de::Error> {
        toml_edit::de::from_str(input)
    }

    /// Report keys in `[[rules]]` tables that no policy field reads.
    ///
    /// Two mistakes end up here. A mistyped or unsupported matcher key, such
    /// as `require = true` under `[rules.workspace]`, loads without error and
    /// enforces nothing. A daemon setting appended after the last rule lands
    /// inside that rule's final sub-table, because a TOML file cannot return
    /// to the top level once a table has started, and is ignored there.
    pub fn unknown_rule_keys(input: &str) -> Result<Vec<UnknownRuleKey>, toml_edit::TomlError> {
        const SUB_TABLES: [(&str, &str, &[&str]); 6] = [
            ("client", "rules.client", ClientMatch::FIELDS),
            ("target", "rules.target", TargetMatch::FIELDS),
            ("workspace", "rules.workspace", WorkspaceMatch::FIELDS),
            (
                "secret_names",
                "rules.secret_names",
                SecretNameMatch::FIELDS,
            ),
            ("identity", "rules.identity", IdentityMatch::FIELDS),
            ("approval", "rules.approval", ApprovalConfig::FIELDS),
        ];

        let document: toml_edit::DocumentMut = input.parse()?;
        let mut findings = Vec::new();
        let Some(rules) = document.get("rules") else {
            return Ok(findings);
        };
        // `[[rules]]` headers and an inline `rules = [{ ... }]` array both count.
        let tables: Vec<&dyn toml_edit::TableLike> = match rules {
            toml_edit::Item::ArrayOfTables(array) => array
                .iter()
                .map(|table| table as &dyn toml_edit::TableLike)
                .collect(),
            toml_edit::Item::Value(toml_edit::Value::Array(array)) => array
                .iter()
                .filter_map(toml_edit::Value::as_inline_table)
                .map(|table| table as &dyn toml_edit::TableLike)
                .collect(),
            _ => Vec::new(),
        };

        for (rule_index, rule) in tables.into_iter().enumerate() {
            let rule_name = rule
                .get("name")
                .and_then(|value| value.as_str())
                .map(str::to_string);
            for (key, _) in rule.iter() {
                if !PolicyRule::FIELDS.contains(&key) {
                    findings.push(UnknownRuleKey {
                        rule_index,
                        rule_name: rule_name.clone(),
                        table: "rules",
                        key: key.to_string(),
                        known: PolicyRule::FIELDS,
                    });
                }
            }
            for (sub, table, known) in SUB_TABLES {
                let Some(sub_table) = rule.get(sub).and_then(|item| item.as_table_like()) else {
                    continue;
                };
                for (key, _) in sub_table.iter() {
                    if !known.contains(&key) {
                        findings.push(UnknownRuleKey {
                            rule_index,
                            rule_name: rule_name.clone(),
                            table,
                            key: key.to_string(),
                            known,
                        });
                    }
                }
            }
        }
        Ok(findings)
    }

    /// Existing CLI policy checks, shared with offline parser robustness tests.
    pub fn validation_errors(&self) -> Vec<String> {
        let mut errors: Vec<String> = Vec::new();
        for (i, rule) in self.rules.iter().enumerate() {
            let prefix = format!("rules[{i}] ({:?})", rule.name);
            if rule.name.is_empty() {
                errors.push(format!("{prefix}: name must be non-empty"));
            }
            if rule.operation_pattern.is_empty() {
                errors.push(format!("{prefix}: operation_pattern must be non-empty"));
            }
            if rule.client_types.is_empty() {
                errors.push(format!("{prefix}: client_types must not be empty"));
            }
            if let Some(ttl) = rule.approval.lease_ttl
                && ttl.as_secs() == 0
            {
                errors.push(format!("{prefix}: approval.lease_ttl must be > 0"));
            }
            if rule.approval.budget.is_some()
                && (rule.approval.require != crate::operation::ApprovalRequirement::FirstUse
                    || rule.approval.budget == Some(0))
            {
                errors.push(format!(
                    "{prefix}: approval.budget requires first_use and must be > 0"
                ));
            }
        }
        errors
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn production_policy_document_preserves_defaults_and_other_subsystem_settings() {
        let document =
            PolicyDocument::from_toml("require_seal = true\n[server]\nport = 42\n").unwrap();
        assert!(document.require_seal);
        assert!(document.rules.is_empty());
        assert!(document.validation_errors().is_empty());
        assert!(!PolicyDocument::from_toml("").unwrap().require_seal);
    }

    #[test]
    fn malformed_and_unknown_matcher_fields_are_rejected() {
        assert!(PolicyDocument::from_toml("[[rules]").is_err());
        assert!(
            PolicyDocument::from_toml(
                r#"
[[rules]]
name = "fixture"
operation_pattern = "*"
[rules.client]
uuid_typo = 12
"#
            )
            .is_err()
        );
    }

    #[test]
    fn semantic_checks_keep_all_existing_cli_failures() {
        let document = PolicyDocument::from_toml(
            r#"
[[rules]]
name = ""
operation_pattern = ""
[rules.approval]
require = "never"
lease_ttl = 0
budget = 0
"#,
        )
        .unwrap();
        let errors = document.validation_errors();
        assert_eq!(errors.len(), 5);
        for field in [
            "name",
            "operation_pattern",
            "client_types",
            "approval.lease_ttl",
            "approval.budget",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(field)),
                "missing {field}"
            );
        }
    }

    /// The two shapes that motivated the lint: a daemon key appended after
    /// the last rule (swallowed by its `[rules.approval]` table) and a matcher
    /// key the engine does not have (`require` under `[rules.workspace]`).
    #[test]
    fn unknown_rule_keys_reports_misplaced_daemon_keys_and_matcher_typos() {
        let appended = r#"
[[rules]]
name = "allow-test-noop"
operation_pattern = "test.noop"
allow = true
client_types = ["agent", "human"]

[rules.approval]
require = "first_use"
factors = ["local_bio"]
lease_ttl = 300

approval_backend = "insecure_auto_approve"
data_dir = "/private/tmp/state"
"#;
        let findings = PolicyDocument::unknown_rule_keys(appended).unwrap();
        assert_eq!(findings.len(), 2, "{findings:?}");
        for (finding, key) in findings.iter().zip(["approval_backend", "data_dir"]) {
            assert_eq!(finding.rule_index, 0);
            assert_eq!(finding.rule_name.as_deref(), Some("allow-test-noop"));
            assert_eq!(finding.table, "rules.approval");
            assert_eq!(finding.key, key);
            assert_eq!(finding.known, ApprovalConfig::FIELDS);
        }
        // The parsed document still loads and still validates: the keys are
        // inert, not invalid, which is exactly why the lint exists.
        let document = PolicyDocument::from_toml(appended).unwrap();
        assert!(document.validation_errors().is_empty());

        let typo = r#"
[[rules]]
name = "first"
operation_pattern = "github.*"
client_types = ["agent"]

[[rules]]
name = "scoped"
operation_pattern = "github.*"
client_types = ["agent"]
lease_ttl = 600

[rules.workspace]
require = true
"#;
        let findings = PolicyDocument::unknown_rule_keys(typo).unwrap();
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert_eq!(findings[0].rule_index, 1);
        assert_eq!(findings[0].table, "rules");
        assert_eq!(findings[0].key, "lease_ttl");
        assert_eq!(findings[1].rule_index, 1);
        assert_eq!(findings[1].rule_name.as_deref(), Some("scoped"));
        assert_eq!(findings[1].table, "rules.workspace");
        assert_eq!(findings[1].key, "require");
        assert_eq!(findings[1].known, WorkspaceMatch::FIELDS);

        // Inline rule syntax is inspected too, and a clean document is quiet.
        let inline = r#"rules = [{ name = "x", operation_pattern = "*", client_types = ["agent"], approval = { require = "always", bogus = 1 } }]"#;
        let findings = PolicyDocument::unknown_rule_keys(inline).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].table, "rules.approval");
        assert_eq!(findings[0].key, "bogus");

        let clean = r#"
require_seal = true

[[rules]]
name = "clean"
operation_pattern = "*"
client_types = ["agent"]

[rules.client]
exe_path = "/usr/bin/claude*"

[rules.target]
fields = { repo = "org/*" }

[rules.workspace]
remote_url_pattern = "*github.com:org/*"
branch_pattern = "main"
require_clean = true

[rules.secret_names]
patterns = ["GH_*"]

[rules.identity]
require_principal = true

[rules.approval]
require = "first_use"
factors = ["local_bio"]
lease_ttl = 300
one_time = false
budget = 2
require_distinct_approver = false
"#;
        assert!(PolicyDocument::unknown_rule_keys(clean).unwrap().is_empty());
        assert!(PolicyDocument::unknown_rule_keys("").unwrap().is_empty());
        assert!(PolicyDocument::unknown_rule_keys("[[rules]").is_err());
    }

    #[test]
    fn reviewed_fuzz_seeds_reach_semantic_validation() {
        let policy = PolicyDocument::from_toml(include_str!(
            "../../../fuzz/corpus/policy_document/allow.toml"
        ))
        .unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert!(policy.validation_errors().is_empty());
        let manifest: crate::task::TaskManifest = serde_json::from_str(include_str!(
            "../../../fuzz/corpus/task_manifest/valid-publish.json"
        ))
        .unwrap();
        assert!(manifest.validate().is_ok());
        assert_eq!(manifest.digest().unwrap().len(), 64);
    }
}
