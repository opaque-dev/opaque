use super::*;
use opaque_core::authority_policy as policy;

fn select(f: &mut Fixture, attempts: u64) -> crate::authority_policy::Config {
    let value = json!({"apiVersion":policy::API_VERSION,"kind":policy::KIND,"metadata":{"name":"cases","namespace":"support"},"spec":{"tenantRef":"fixture","connectorRef":"support","authority":{"operation":policy::OPERATION,"allowedStatuses":["closed","resolved"],"maxResources":2,"maxAttempts":attempts,"maxDuration":"1h"},"approval":{"scope":"Required","action":"EveryAction","reviewerRef":"ops"}}});
    let path = f.directory.path().join("authority-policy.json");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let compiled = policy::read(&path).unwrap();
    let config = crate::authority_policy::Config {
        path,
        digest: compiled.digest,
        name: "cases".into(),
        namespace: "support".into(),
        tenant_ref: "fixture".into(),
        connector_ref: "support".into(),
        reviewer_ref: "ops".into(),
        reviewer_id: f.runtime.config.reviewer_id.clone(),
        reviewer_public_key: f.runtime.config.reviewer_public_key.clone(),
        generation: f.runtime.config.generation,
        profile: f.runtime.config.profile.clone(),
    };
    f.runtime.config = config.resolve(&f.tenant).unwrap();
    config
}

#[tokio::test]
async fn manifest_activation_reapply_and_rollback_never_reissue_consumed_or_revoked_authority() {
    for unknown in [false, true] {
        let provider = Provider::new(vec![
            read_reply(),
            if unknown {
                vec![]
            } else {
                reply("200 OK", &json!({}))
            },
        ])
        .await;
        let mut f = Fixture::new(&provider, true);
        let binding = select(&mut f, 2);
        let f = f.restart();
        let snapshot = f.runtime.snapshot(&f.context).unwrap();
        assert!(snapshot["ledger"]["scopes"].as_array().unwrap().is_empty());
        assert_eq!(snapshot["authority_policy"]["digest"], binding.digest);
        assert_eq!(
            snapshot["authority_policy"]["identity"]["namespace"],
            "support"
        );
        let (scope, issuance) = f.issued(1);
        let review = f.prepared(&scope, &issuance, "manifest-request").await;
        f.approve(&review);
        let outcome = f.execute(&review, &issuance).await.unwrap();
        assert_eq!(
            outcome["state"],
            if unknown { "unknown" } else { "api_accepted" }
        );
        let mut f = f.restart();
        assert_eq!(f.execute(&review, &issuance).await.unwrap(), outcome);
        assert_eq!(
            f.runtime
                .ledger
                .get_scope(&scope.scope_id)
                .unwrap()
                .charged_attempts,
            1
        );
        // A semantic policy update rejects old review authority. Returning to the
        // previous policy may match its identity, but never resets execution state.
        select(&mut f, 1);
        let mut f = f.restart();
        assert!(
            f.runtime
                .grant(&scope.scope_id, f.context.sub.as_str())
                .is_err()
        );
        assert!(f.execute(&review, &issuance).await.is_err());
        select(&mut f, 2);
        let f = f.restart();
        assert_eq!(f.execute(&review, &issuance).await.unwrap(), outcome);
        f.runtime
            .ledger
            .revoke(&scope.scope_id, now_unix())
            .unwrap();
        let mut f = f.restart();
        select(&mut f, 1);
        let mut f = f.restart();
        select(&mut f, 2);
        let f = f.restart();
        assert!(
            f.runtime
                .grant(&scope.scope_id, f.context.sub.as_str())
                .is_err()
        );
        assert_eq!(f.execute(&review, &issuance).await.unwrap(), outcome);
        let retained = f.runtime.ledger.get_scope(&scope.scope_id).unwrap();
        assert_eq!(retained.charged_attempts, 1);
        assert!(retained.revoked_at.is_some());
        assert_eq!(provider.finish().await.len(), 2);
    }
}
