use serde_json::{Value, json};
/// Portable schema for user-authored documents. Kubernetes adapters should use
/// the strict `spec` subtree and strip only known API-server metadata/status
/// before invoking the same compiler; never prune unknown spec fields to valid.
pub fn json_schema() -> Value {
    let reference = json!({"type":"string","minLength":1,"maxLength":63,"pattern":"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"});
    let limits = json!({
        "maxResources":{"type":"integer","minimum":1,"maximum":100},
        "maxAttempts":{"type":"integer","minimum":1,"maximum":10000},
        "maxDuration":{"type":"string","minLength":2,"maxLength":8,"pattern":"^(([1-9][0-9]{0,3}|[1-7][0-9]{4}|8[0-5][0-9]{3}|86[0-3][0-9]{2}|86400)s|([1-9][0-9]{0,2}|1[0-3][0-9]{2}|14[0-3][0-9]|1440)m|([1-9]|1[0-9]|2[0-4])h)$"}
    });
    let mut support = json!({
        "operation":{"type":"string","enum":[super::OPERATION]},
        "allowedStatuses":{"type":"array","minItems":1,"maxItems":3,"uniqueItems":true,"items":{"type":"string","enum":["open","resolved","closed"]}}
    });
    let mut dispatch = json!({
        "operation":{"type":"string","enum":[super::DISPATCH_OPERATION]},
        "workflows":{"type":"array","minItems":1,"maxItems":super::MAX_WORKFLOWS,"uniqueItems":true,"items":{
            "type":"object","additionalProperties":false,"required":["repository","path","ref"],"properties":{
                "repository":{"type":"string","minLength":3,"maxLength":201,"pattern":"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$"},
                "path":{"type":"string","minLength":23,"maxLength":118,"pattern":"^\\.github/workflows/[A-Za-z0-9_.-]{1,95}\\.(yml|yaml)$"},
                "ref":{"type":"string","minLength":1,"maxLength":200,"pattern":"^[A-Za-z0-9_-][A-Za-z0-9_./-]{0,199}$"}
            }}}
    });
    for (target, source) in [(&mut support, &limits), (&mut dispatch, &limits)] {
        for (key, value) in source.as_object().expect("limits object") {
            target[key] = value.clone();
        }
    }
    json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "$id":"https://opaque.dev/schemas/authority-policy-v1alpha1.json",
        "title":"AuthorityPolicy v1alpha1",
        "type":"object","additionalProperties":false,
        "required":["apiVersion","kind","metadata","spec"],
        "properties":{
            "apiVersion":{"type":"string","enum":[super::API_VERSION]},
            "kind":{"type":"string","enum":[super::KIND]},
            "metadata":{"type":"object","additionalProperties":false,"required":["name","namespace"],"properties":{"name":reference,"namespace":reference}},
            "spec":{"type":"object","additionalProperties":false,"required":["tenantRef","connectorRef","authority","approval"],"properties":{
                "tenantRef":reference,"connectorRef":reference,
                "mode":{"type":"string","enum":["Enforce"],"default":"Enforce"},
                "evaluators":{"type":"array","maxItems":0,"items":{},"default":[]},
                "authority":{"oneOf":[
                    {"type":"object","additionalProperties":false,"required":["operation","allowedStatuses","maxResources","maxAttempts","maxDuration"],"properties":support},
                    {"type":"object","additionalProperties":false,"required":["operation","workflows","maxResources","maxAttempts","maxDuration"],"properties":dispatch}
                ]},
                "approval":{"type":"object","additionalProperties":false,"required":["scope","reviewerRef"],"properties":{
                    "scope":{"type":"string","enum":["Required"]},
                    "action":{"type":"string","enum":["EveryAction","WithinApprovedScope"],"default":"EveryAction"},
                    "reviewerRef":reference
                }}
            }}
        }
    })
}
