//! Model-facing descriptions of tool argument validation failures. A message
//! names the failing field path and the violated constraint from the published
//! schema. It never quotes a supplied value or a caller-chosen property name,
//! so a mistaken or hostile argument cannot place text in the response.
use jsonschema::error::{TypeKind, ValidationErrorKind};
use jsonschema::{ValidationError, Validator};
use serde_json::Value;

/// Prefix kept from the former generic rejection so existing clients still
/// recognize a schema failure.
pub const SCHEMA_MISMATCH: &str = "tool arguments do not match the input schema";
const MAX_REPORTED_FAILURES: usize = 3;
const MAX_LISTED_OPTIONS: usize = 8;

/// `None` when `arguments` satisfy `validator`; otherwise a bounded message
/// naming up to three failing field paths (JSON pointers, `/` for the whole
/// argument object) and their constraints. `schema` must be the document the
/// validator was compiled from; it supplies the allowed field names when a
/// closed object receives an unexpected field.
pub fn describe_failures(
    schema: &Value,
    validator: &Validator,
    arguments: &Value,
) -> Option<String> {
    let mut details = Vec::new();
    let mut total = 0usize;
    for error in validator.iter_errors(arguments) {
        total += 1;
        if details.len() < MAX_REPORTED_FAILURES {
            details.push(describe(schema, &error));
        }
    }
    if total == 0 {
        return None;
    }
    let mut message = format!("{SCHEMA_MISMATCH}: {}", details.join("; "));
    if total > MAX_REPORTED_FAILURES {
        message.push_str(&format!("; and {} more", total - MAX_REPORTED_FAILURES));
    }
    Some(message)
}

fn describe(schema: &Value, error: &ValidationError<'_>) -> String {
    let path = error.instance_path().as_str();
    let field = if path.is_empty() { "/" } else { path };
    match error.kind() {
        ValidationErrorKind::Required { property } => {
            // The property name comes from the schema, not the caller.
            let name = property.as_str().unwrap_or_default();
            format!("missing required field \"{path}/{name}\"")
        }
        ValidationErrorKind::Type { kind } => {
            format!("\"{field}\" must be of type {}", type_names(kind))
        }
        ValidationErrorKind::AdditionalProperties { unexpected }
        | ValidationErrorKind::UnevaluatedProperties { unexpected } => {
            let count = unexpected.len();
            let noun = if count == 1 { "field" } else { "fields" };
            match allowed_fields(schema, error.schema_path().as_str()) {
                Some(allowed) if !allowed.is_empty() => format!(
                    "\"{field}\" has {count} unexpected {noun}; allowed fields: {}",
                    allowed.join(", ")
                ),
                _ => format!("\"{field}\" has {count} unexpected {noun}; no fields are allowed"),
            }
        }
        ValidationErrorKind::Enum { options } => {
            format!("\"{field}\" must be one of {}", list_options(options))
        }
        ValidationErrorKind::Constant { expected_value } => {
            format!("\"{field}\" must equal {expected_value}")
        }
        ValidationErrorKind::MinLength { limit } => {
            format!("\"{field}\" must have at least {limit} characters")
        }
        ValidationErrorKind::MaxLength { limit } => {
            format!("\"{field}\" must have at most {limit} characters")
        }
        ValidationErrorKind::Minimum { limit } => format!("\"{field}\" must be at least {limit}"),
        ValidationErrorKind::Maximum { limit } => format!("\"{field}\" must be at most {limit}"),
        ValidationErrorKind::ExclusiveMinimum { limit } => {
            format!("\"{field}\" must be greater than {limit}")
        }
        ValidationErrorKind::ExclusiveMaximum { limit } => {
            format!("\"{field}\" must be less than {limit}")
        }
        ValidationErrorKind::MultipleOf { multiple_of } => {
            format!("\"{field}\" must be a multiple of {multiple_of}")
        }
        ValidationErrorKind::MinItems { limit } => {
            format!("\"{field}\" must have at least {limit} items")
        }
        ValidationErrorKind::MaxItems { limit } => {
            format!("\"{field}\" must have at most {limit} items")
        }
        ValidationErrorKind::MinProperties { limit } => {
            format!("\"{field}\" must have at least {limit} fields")
        }
        ValidationErrorKind::MaxProperties { limit } => {
            format!("\"{field}\" must have at most {limit} fields")
        }
        ValidationErrorKind::Pattern { pattern } => {
            format!("\"{field}\" must match the pattern {pattern}")
        }
        ValidationErrorKind::UniqueItems => {
            format!("\"{field}\" must not contain duplicate items")
        }
        _ => format!(
            "\"{field}\" violates the {} constraint",
            keyword(error.schema_path().as_str())
        ),
    }
}

fn type_names(kind: &TypeKind) -> String {
    match kind {
        TypeKind::Single(json_type) => json_type.to_string(),
        TypeKind::Multiple(set) => set
            .iter()
            .map(|json_type| json_type.to_string())
            .collect::<Vec<_>>()
            .join(" or "),
    }
}

/// Property names declared beside the failing `additionalProperties` keyword.
/// These come from the published schema, so listing them discloses nothing
/// about the call.
fn allowed_fields(schema: &Value, schema_path: &str) -> Option<Vec<String>> {
    let object_path = schema_path
        .strip_suffix("/additionalProperties")
        .or_else(|| schema_path.strip_suffix("/unevaluatedProperties"))?;
    let mut names: Vec<String> = schema
        .pointer(object_path)?
        .get("properties")?
        .as_object()?
        .keys()
        .cloned()
        .collect();
    names.sort();
    Some(names)
}

fn list_options(options: &Value) -> String {
    let Some(values) = options.as_array() else {
        return options.to_string();
    };
    let mut listed: Vec<String> = values
        .iter()
        .take(MAX_LISTED_OPTIONS)
        .map(Value::to_string)
        .collect();
    if values.len() > MAX_LISTED_OPTIONS {
        listed.push(format!("and {} more", values.len() - MAX_LISTED_OPTIONS));
    }
    listed.join(", ")
}

fn keyword(schema_path: &str) -> &str {
    match schema_path.rsplit('/').next() {
        Some(last) if !last.is_empty() => last,
        _ => "schema",
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use serde_json::json;

    fn failure(schema: Value, arguments: Value) -> String {
        let validator = jsonschema::validator_for(&schema).unwrap();
        describe_failures(&schema, &validator, &arguments).expect("arguments must be rejected")
    }

    #[test]
    fn valid_arguments_produce_no_message() {
        let schema = json!({"type":"object","required":["profile"],"properties":{"profile":{"type":"string"}}});
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert_eq!(
            describe_failures(&schema, &validator, &json!({"profile":"dev"})),
            None
        );
    }

    #[test]
    fn missing_required_field_is_named_by_pointer() {
        let schema = json!({"type":"object","required":["profile"],"properties":{"profile":{"type":"string"}}});
        assert_eq!(
            failure(schema.clone(), json!({})),
            format!("{SCHEMA_MISMATCH}: missing required field \"/profile\"")
        );
        let nested = json!({"type":"object","properties":{"manifest":{"type":"object","required":["title"],"properties":{"title":{"type":"string"}}}}});
        assert_eq!(
            failure(nested, json!({"manifest":{}})),
            format!("{SCHEMA_MISMATCH}: missing required field \"/manifest/title\"")
        );
    }

    #[test]
    fn constraint_messages_name_the_path_and_never_quote_values() {
        let schema = json!({"type":"object","additionalProperties":false,"properties":{
            "task_id":{"type":"string","minLength":3,"maxLength":5,"pattern":"^[a-z]+$"},
            "count":{"type":"integer","minimum":1,"maximum":9},
            "level":{"type":"string","enum":["low","high"]},
            "environment":{"const":"staging"},
            "items":{"type":"array","minItems":1,"maxItems":2,"uniqueItems":true},
            "either":{"type":["string","null"]},
        }});
        let secret = "synthetic-private-value-7f3a";
        for (arguments, expected) in [
            (
                json!({"task_id":null}),
                "\"/task_id\" must be of type string",
            ),
            (
                json!({"task_id":"ab"}),
                "\"/task_id\" must have at least 3 characters",
            ),
            (
                json!({"task_id":"abcdef"}),
                "\"/task_id\" must have at most 5 characters",
            ),
            (
                json!({"task_id":"AB12"}),
                "\"/task_id\" must match the pattern ^[a-z]+$",
            ),
            (json!({"count":0}), "\"/count\" must be at least 1"),
            (json!({"count":10}), "\"/count\" must be at most 9"),
            (
                json!({"level":secret}),
                "\"/level\" must be one of \"low\", \"high\"",
            ),
            (
                json!({"environment":secret}),
                "\"/environment\" must equal \"staging\"",
            ),
            (json!({"items":[]}), "\"/items\" must have at least 1 items"),
            (
                json!({"items":[1,2,3]}),
                "\"/items\" must have at most 2 items",
            ),
            (
                json!({"items":[1,1]}),
                "\"/items\" must not contain duplicate items",
            ),
            (
                json!({"either":7}),
                "\"/either\" must be of type null or string",
            ),
            (
                json!({secret:"x"}),
                "\"/\" has 1 unexpected field; allowed fields: count, either, environment, items, level, task_id",
            ),
        ] {
            let message = failure(schema.clone(), arguments.clone());
            assert_eq!(
                message,
                format!("{SCHEMA_MISMATCH}: {expected}"),
                "{arguments}"
            );
            assert!(!message.contains(secret), "{message}");
        }
    }

    #[test]
    fn unexpected_fields_are_counted_not_echoed() {
        let closed = json!({"type":"object","additionalProperties":false,"properties":{}});
        assert_eq!(
            failure(closed, json!({"secret-a":1,"secret-b":2})),
            format!("{SCHEMA_MISMATCH}: \"/\" has 2 unexpected fields; no fields are allowed")
        );
        let nested = json!({"type":"object","properties":{"manifest":{"type":"object","additionalProperties":false,"properties":{"title":{}}}}});
        assert_eq!(
            failure(nested, json!({"manifest":{"forged":true}})),
            format!(
                "{SCHEMA_MISMATCH}: \"/manifest\" has 1 unexpected field; allowed fields: title"
            )
        );
    }

    #[test]
    fn reports_are_bounded_to_three_failures() {
        let schema = json!({"type":"object","required":["a","b","c","d","e"]});
        assert_eq!(
            failure(schema, json!({})),
            format!(
                "{SCHEMA_MISMATCH}: missing required field \"/a\"; missing required field \"/b\"; missing required field \"/c\"; and 2 more"
            )
        );
    }

    #[test]
    fn unmapped_constraints_fall_back_to_the_schema_keyword() {
        let schema = json!({"type":"object","properties":{"flag":{"not":{"type":"boolean"}}}});
        assert_eq!(
            failure(schema, json!({"flag":true})),
            format!("{SCHEMA_MISMATCH}: \"/flag\" violates the not constraint")
        );
        let options: Vec<Value> = (0..10).map(|n| json!(n)).collect();
        assert_eq!(
            list_options(&Value::Array(options)),
            "0, 1, 2, 3, 4, 5, 6, 7, and 2 more"
        );
    }
}
