#![no_main]
use libfuzzer_sys::fuzz_target;
use opaque_core::policy::PolicyEngine;
use opaque_core::policy_document::PolicyDocument;

fuzz_target!(|data: &[u8]| {
    if data.len() > opaque_core::MAX_FRAME_LENGTH {
        return;
    }
    if let Ok(compiled) = opaque_core::authority_policy::compile(data) {
        let canonical = serde_json::to_vec(&compiled.policy).unwrap();
        assert_eq!(opaque_core::authority_policy::compile(&canonical).unwrap(), compiled);
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(document) = PolicyDocument::from_toml(text) else {
        return;
    };
    let errors = document.validation_errors();
    let canonical = serde_json::to_vec(&document).unwrap();
    let restored: PolicyDocument = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(errors, restored.validation_errors());
    assert_eq!(serde_json::to_vec(&restored).unwrap(), canonical);
    let engine = PolicyEngine::with_rules(document.rules);
    let restored = PolicyEngine::with_rules(restored.rules);
    assert_eq!(engine.digest().unwrap(), restored.digest().unwrap());
});
