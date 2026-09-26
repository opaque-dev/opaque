//! Scope review transport over the existing pinned-TLS/workstation enrollment.
//! The host service holds current identity/enrollment/policy fences. Transport
//! bearer authentication alone is never a human approval or scope authorization.
use super::*;
use axum::response::Response;
use opaque_core::scope_review::{DecisionReceipt, ReviewerDecision, SignedReview};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeReviewServiceError {
    Unavailable,
    NotFound,
    Forbidden,
    Conflict,
}
pub trait ScopeReviewService: Send + Sync {
    fn key(&self, device: &PairedDevice) -> Result<ScopeReviewKey, ScopeReviewServiceError>;
    fn pending(&self, device: &PairedDevice) -> Result<Vec<SignedReview>, ScopeReviewServiceError>;
    fn get(
        &self,
        device: &PairedDevice,
        round_id: &str,
    ) -> Result<SignedReview, ScopeReviewServiceError>;
    fn submit(
        &self,
        device: &PairedDevice,
        round_id: &str,
        response: &ReviewerDecision,
    ) -> Result<DecisionReceipt, ScopeReviewServiceError>;
    fn receipt(
        &self,
        device: &PairedDevice,
        round_id: &str,
    ) -> Result<Option<DecisionReceipt>, ScopeReviewServiceError>;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeReviewKey {
    pub broker_public_key: String,
    pub reviewer_id: String,
    pub device_id: String,
    pub reviewer_public_key: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingScopeReviews {
    pub reviews: Vec<SignedReview>,
}

pub(super) fn routes() -> Router<Arc<ServerState>> {
    Router::new()
        .route("/workstation/scopes/key", get(key))
        .route("/workstation/scopes/pending", get(pending))
        .route("/workstation/scopes/{round_id}", get(review))
        .route("/workstation/scopes/{round_id}/respond", post(respond))
        .route("/workstation/scopes/{round_id}/receipt", get(receipt))
        .layer(axum::extract::DefaultBodyLimit::max(8192))
}
fn status(error: ScopeReviewServiceError) -> StatusCode {
    match error {
        ScopeReviewServiceError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        ScopeReviewServiceError::NotFound => StatusCode::NOT_FOUND,
        ScopeReviewServiceError::Forbidden => StatusCode::FORBIDDEN,
        ScopeReviewServiceError::Conflict => StatusCode::CONFLICT,
    }
}
fn service(state: &ServerState) -> Result<&dyn ScopeReviewService, StatusCode> {
    state
        .scope_reviews
        .as_deref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)
}
fn auth(state: &ServerState, headers: &HeaderMap) -> Result<PairedDevice, StatusCode> {
    if headers.contains_key("origin")
        || headers.get_all("authorization").iter().count() != 1
        || headers.get_all("x-opaque-device").iter().count() != 1
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let id = validate_auth(state, headers)?;
    state
        .pairing
        .workstation_device(&id)
        .map_err(|_| StatusCode::FORBIDDEN)
}
fn binding(
    state: &ServerState,
    device: &PairedDevice,
    review: &SignedReview,
) -> Result<(), StatusCode> {
    let authority = &review.document.authority;
    if authority.owner.broker_id != state.pairing.server_id()
        || authority.device_id != device.device_id
        || authority.reviewer_public_key != device.public_key_hex
        || device.paired_by.as_deref() != Some(authority.reviewer_id.as_str())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}
fn private<T: Serialize>(value: T) -> Response {
    (
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(value),
    )
        .into_response()
}
async fn key(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let device = auth(&state, &headers)?;
    let key = service(&state)?.key(&device).map_err(status)?;
    if key.device_id != device.device_id
        || key.reviewer_public_key != device.public_key_hex
        || device.paired_by.as_deref() != Some(key.reviewer_id.as_str())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(private(key))
}
async fn pending(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let device = auth(&state, &headers)?;
    let service = service(&state)?;
    let reviews = service.pending(&device).map_err(status)?;
    if reviews.len() > 1 {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let expected = service.key(&device).map_err(status)?.broker_public_key;
    for review in &reviews {
        binding(&state, &device, review)?;
        review
            .verify(&expected, opaque_core::identity::now_unix())
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    }
    Ok(private(PendingScopeReviews { reviews }))
}
async fn review(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, StatusCode> {
    let device = auth(&state, &headers)?;
    let service = service(&state)?;
    let review = service.get(&device, &id).map_err(status)?;
    if review.document.round_id != id {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    binding(&state, &device, &review)?;
    review
        .verify(
            &service.key(&device).map_err(status)?.broker_public_key,
            opaque_core::identity::now_unix(),
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(private(review))
}
async fn respond(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<ReviewerDecision>,
) -> Result<Response, StatusCode> {
    let device = auth(&state, &headers)?;
    let service = service(&state)?;
    if body.round_id != id
        || body.device_id != device.device_id
        || device.paired_by.as_deref() != Some(body.reviewer_id.as_str())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let receipt = service.submit(&device, &id, &body).map_err(status)?;
    binding(&state, &device, &receipt.review)?;
    if receipt.response != body {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    receipt
        .verify(&service.key(&device).map_err(status)?.broker_public_key)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(private(receipt))
}
async fn receipt(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, StatusCode> {
    let device = auth(&state, &headers)?;
    let service = service(&state)?;
    let receipt = service
        .receipt(&device, &id)
        .map_err(status)?
        .ok_or(StatusCode::NOT_FOUND)?;
    binding(&state, &device, &receipt.review)?;
    if receipt.review.document.round_id != id {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    receipt
        .verify(&service.key(&device).map_err(status)?.broker_public_key)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(private(receipt))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::pairing::{WorkstationApproverConfig, store::DeviceStore};
    use ed25519_dalek::{Signer, SigningKey};
    use opaque_core::workstation::{EnrollmentRequest, enrollment_bytes, hex};
    struct Keys {
        mismatch: bool,
    }
    impl ScopeReviewService for Keys {
        fn key(&self, device: &PairedDevice) -> Result<ScopeReviewKey, ScopeReviewServiceError> {
            Ok(ScopeReviewKey {
                broker_public_key: "a".repeat(64),
                reviewer_id: if self.mismatch {
                    "wrong".into()
                } else {
                    device.paired_by.clone().unwrap()
                },
                device_id: device.device_id.clone(),
                reviewer_public_key: device.public_key_hex.clone(),
            })
        }
        fn pending(&self, _: &PairedDevice) -> Result<Vec<SignedReview>, ScopeReviewServiceError> {
            Err(ScopeReviewServiceError::Unavailable)
        }
        fn get(&self, _: &PairedDevice, _: &str) -> Result<SignedReview, ScopeReviewServiceError> {
            Err(ScopeReviewServiceError::NotFound)
        }
        fn submit(
            &self,
            _: &PairedDevice,
            _: &str,
            _: &ReviewerDecision,
        ) -> Result<DecisionReceipt, ScopeReviewServiceError> {
            Err(ScopeReviewServiceError::Forbidden)
        }
        fn receipt(
            &self,
            _: &PairedDevice,
            _: &str,
        ) -> Result<Option<DecisionReceipt>, ScopeReviewServiceError> {
            Err(ScopeReviewServiceError::NotFound)
        }
    }
    fn fixture(
        workstation: bool,
        service: Option<Arc<dyn ScopeReviewService>>,
    ) -> (tempfile::TempDir, Arc<ServerState>, HeaderMap) {
        let dir = tempfile::tempdir().unwrap();
        let device_key = SigningKey::from_bytes(&[9; 32]);
        let pairing = Arc::new(PairingManager::new(
            "broker-fixture".into(),
            SigningKey::from_bytes(&[8; 32]),
            0,
            DeviceStore::new(dir.path().join("devices.json"), vec![7; 32]),
        ));
        let (device_id, token) = if workstation {
            let key = hex(device_key.verifying_key().as_bytes());
            pairing
                .enroll_workstation(&WorkstationApproverConfig {
                    public_key_hex: key.clone(),
                    name: "Fixture".into(),
                    principal_id: Some("reviewer".into()),
                })
                .unwrap();
            let challenge = pairing.begin_workstation_enrollment(&key).unwrap();
            let response = pairing
                .complete_workstation_enrollment(&EnrollmentRequest {
                    public_key_hex: key,
                    nonce: challenge.nonce.clone(),
                    signature: hex(&device_key.sign(&enrollment_bytes(&challenge)).to_bytes()),
                })
                .unwrap();
            (response.device_id, response.token)
        } else {
            let (_, nonce) = pairing.generate_qr_payload(Some("reviewer".into()));
            let (device, token) = pairing
                .complete_pairing(
                    &nonce,
                    device_key.verifying_key().as_bytes(),
                    "Legacy fixture",
                )
                .unwrap();
            pairing.confirm_device(&device.device_id).unwrap();
            (device.device_id, token)
        };
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers.insert("x-opaque-device", device_id.parse().unwrap());
        let state = Arc::new(ServerState {
            pending: Mutex::new(HashMap::new()),
            pairing,
            timeout: Duration::from_secs(60),
            workstation_pending: std::sync::Mutex::new(HashMap::new()),
            remote: None,
            scope_reviews: service,
        });
        (dir, state, headers)
    }
    #[tokio::test]
    async fn scope_key_requires_workstation_not_legacy_pairing() {
        let (_dir, state, headers) = fixture(false, Some(Arc::new(Keys { mismatch: false })));
        assert_eq!(
            key(State(state), headers).await.unwrap_err(),
            StatusCode::FORBIDDEN
        );
        let (_dir, state, headers) = fixture(true, Some(Arc::new(Keys { mismatch: false })));
        let response = key(State(state), headers).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    }
    #[tokio::test]
    async fn scope_routes_reject_browser_duplicate_auth_and_absent_service() {
        let (_dir, state, mut headers) = fixture(true, None);
        assert_eq!(
            key(State(state.clone()), headers.clone())
                .await
                .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        headers.insert("origin", "https://example.invalid".parse().unwrap());
        assert_eq!(
            key(State(state.clone()), headers.clone())
                .await
                .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        headers.remove("origin");
        headers.append("authorization", "Bearer second".parse().unwrap());
        assert_eq!(
            key(State(state), headers).await.unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
    }
    #[tokio::test]
    async fn scope_key_rejects_host_response_for_another_principal() {
        let (_dir, state, headers) = fixture(true, Some(Arc::new(Keys { mismatch: true })));
        assert_eq!(
            key(State(state), headers).await.unwrap_err(),
            StatusCode::FORBIDDEN
        );
    }

    /// Deliberately controllable host replies test the transport's independent
    /// bindings. Software signatures exercise bytes and do not claim presence.
    struct Replies {
        identity: ScopeReviewKey,
        pending: Vec<SignedReview>,
        review: SignedReview,
        receipt: Option<DecisionReceipt>,
        error: Option<ScopeReviewServiceError>,
        submissions: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl ScopeReviewService for Replies {
        fn key(&self, _: &PairedDevice) -> Result<ScopeReviewKey, ScopeReviewServiceError> {
            if let Some(error) = self.error {
                return Err(error);
            }
            Ok(ScopeReviewKey {
                broker_public_key: self.identity.broker_public_key.clone(),
                reviewer_id: self.identity.reviewer_id.clone(),
                device_id: self.identity.device_id.clone(),
                reviewer_public_key: self.identity.reviewer_public_key.clone(),
            })
        }
        fn pending(&self, _: &PairedDevice) -> Result<Vec<SignedReview>, ScopeReviewServiceError> {
            Ok(self.pending.clone())
        }
        fn get(&self, _: &PairedDevice, _: &str) -> Result<SignedReview, ScopeReviewServiceError> {
            Ok(self.review.clone())
        }
        fn submit(
            &self,
            _: &PairedDevice,
            _: &str,
            _: &ReviewerDecision,
        ) -> Result<DecisionReceipt, ScopeReviewServiceError> {
            self.submissions
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.receipt
                .clone()
                .ok_or(ScopeReviewServiceError::NotFound)
        }
        fn receipt(
            &self,
            _: &PairedDevice,
            _: &str,
        ) -> Result<Option<DecisionReceipt>, ScopeReviewServiceError> {
            Ok(self.receipt.clone())
        }
    }

    struct RouteFixture {
        _directory: tempfile::TempDir,
        state: Arc<ServerState>,
        headers: HeaderMap,
        review: SignedReview,
        decision: ReviewerDecision,
        submissions: Arc<std::sync::atomic::AtomicUsize>,
    }
    fn replies(change: impl FnOnce(&mut Replies)) -> RouteFixture {
        use opaque_core::{
            scope::{
                AuthorityOwner, FieldConstraint, MinimumApproval, ScopeGrant, ScopeRequirements,
            },
            scope_review::{
                Decision, EMPTY_RECEIPT_DIGEST, ReviewAuthority, ReviewDocument, ReviewSubject,
            },
        };
        let (directory, mut state, headers) = fixture(true, None);
        let device = auth(&state, &headers).unwrap();
        let broker = SigningKey::from_bytes(&[10; 32]);
        let reviewer = SigningKey::from_bytes(&[9; 32]);
        let now = opaque_core::identity::now_unix();
        let owner = AuthorityOwner {
            tenant_id: "tenant-fixture".into(),
            broker_id: state.pairing.server_id().into(),
            generation: "1".into(),
        };
        let grant = ScopeGrant {
            schema_version: 1,
            scope_id: "scope-fixture".into(),
            root_id: "scope-fixture".into(),
            parent_id: None,
            owner: owner.clone(),
            issuer: "requester".into(),
            subject: "requester".into(),
            operation: "support.case.set_status".into(),
            provider_profile_digest: "1".repeat(64),
            resources: vec!["case1".into()],
            fields: vec![FieldConstraint {
                field: "status".into(),
                allowed_values: vec!["closed".into()],
            }],
            not_before: now,
            expires_at: now + 600,
            delegations_remaining: 0,
            max_charged_attempts: 1,
            max_distinct_resources: 1,
            requirements: ScopeRequirements {
                policy_digest: "2".repeat(64),
                minimum_approval: MinimumApproval::ExactAction,
                evaluator_checks: vec![],
            },
            issuance_receipt_digest: EMPTY_RECEIPT_DIGEST.into(),
        };
        let authority = ReviewAuthority {
            owner,
            requester_id: "requester".into(),
            reviewer_id: device.paired_by.clone().unwrap(),
            device_id: device.device_id.clone(),
            reviewer_public_key: device.public_key_hex.clone(),
            required_role: "approver".into(),
            policy_digest: "2".repeat(64),
            authority_epoch: 1,
            enrollment_epoch: 1,
        };
        let review = SignedReview::sign(
            ReviewDocument::new(
                uuid::Uuid::new_v4().to_string(),
                "a".repeat(64),
                now,
                now + 300,
                authority,
                ReviewSubject::issuance(&grant).unwrap(),
            )
            .unwrap(),
            &broker,
        )
        .unwrap();
        let decision = ReviewerDecision::sign(
            &review,
            &review.broker_public_key,
            &reviewer,
            Decision::Approve,
            now,
        )
        .unwrap();
        let receipt =
            DecisionReceipt::sign(review.clone(), decision.clone(), now, &broker).unwrap();
        let submissions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut service = Replies {
            identity: ScopeReviewKey {
                broker_public_key: review.broker_public_key.clone(),
                reviewer_id: device.paired_by.unwrap(),
                device_id: device.device_id,
                reviewer_public_key: device.public_key_hex,
            },
            pending: vec![review.clone()],
            review: review.clone(),
            receipt: Some(receipt),
            error: None,
            submissions: submissions.clone(),
        };
        change(&mut service);
        Arc::get_mut(&mut state).unwrap().scope_reviews = Some(Arc::new(service));
        RouteFixture {
            _directory: directory,
            state,
            headers,
            review,
            decision,
            submissions,
        }
    }

    #[tokio::test]
    async fn enrolled_scope_routes_return_signed_bytes_and_bound_submission_over_http() {
        let fixture = replies(|_| {});
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let router = routes().with_state(fixture.state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let id = &fixture.review.document.round_id;
        for path in [
            "/workstation/scopes/key".to_owned(),
            "/workstation/scopes/pending".into(),
            format!("/workstation/scopes/{id}"),
            format!("/workstation/scopes/{id}/receipt"),
        ] {
            let response = client
                .get(format!("{base}{path}"))
                .headers(fixture.headers.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(response.headers()["cache-control"], "no-store");
            let value: serde_json::Value = response.json().await.unwrap();
            if path.ends_with("/pending") {
                assert_eq!(
                    value["reviews"][0],
                    serde_json::to_value(&fixture.review).unwrap()
                );
            } else if path.ends_with("/receipt") {
                let receipt: DecisionReceipt = serde_json::from_value(value).unwrap();
                receipt.verify(&fixture.review.broker_public_key).unwrap();
            } else if path.ends_with(id) {
                assert_eq!(value, serde_json::to_value(&fixture.review).unwrap());
            }
        }
        let response = client
            .post(format!("{base}/workstation/scopes/{id}/respond"))
            .headers(fixture.headers.clone())
            .json(&fixture.decision)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let receipt: DecisionReceipt = response.json().await.unwrap();
        assert_eq!(receipt.response, fixture.decision);
        receipt.verify(&fixture.review.broker_public_key).unwrap();
        let oversized = client
            .post(format!("{base}/workstation/scopes/{id}/respond"))
            .headers(fixture.headers.clone())
            .header("content-type", "application/json")
            .body(" ".repeat(8193))
            .send()
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            fixture
                .submissions
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn pending_reviews_cannot_cross_broker_device_key_or_reviewer_binding() {
        for change in 0..4 {
            let fixture = replies(|service| {
                let authority = &mut service.pending[0].document.authority;
                match change {
                    0 => authority.owner.broker_id = "other-broker".into(),
                    1 => authority.device_id = "other-device".into(),
                    2 => authority.reviewer_public_key = "f".repeat(64),
                    _ => authority.reviewer_id = "other-reviewer".into(),
                }
            });
            assert_eq!(
                pending(State(fixture.state), fixture.headers)
                    .await
                    .unwrap_err(),
                StatusCode::FORBIDDEN
            );
        }
        let fixture = replies(|service| service.pending.push(service.review.clone()));
        assert_eq!(
            pending(State(fixture.state), fixture.headers)
                .await
                .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let fixture = replies(|service| service.pending.clear());
        assert_eq!(
            pending(State(fixture.state), fixture.headers)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn route_path_and_response_echo_are_independent_of_host_signatures() {
        for change in 0..3 {
            let fixture = replies(|_| {});
            let id = fixture.review.document.round_id.clone();
            let mut decision = fixture.decision;
            match change {
                0 => decision.round_id = uuid::Uuid::new_v4().to_string(),
                1 => decision.device_id = "other-device".into(),
                _ => decision.reviewer_id = "other-reviewer".into(),
            }
            assert_eq!(
                respond(
                    State(fixture.state),
                    fixture.headers,
                    AxumPath(id),
                    Json(decision)
                )
                .await
                .unwrap_err(),
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                fixture
                    .submissions
                    .load(std::sync::atomic::Ordering::SeqCst),
                0
            );
        }
        let fixture = replies(|_| {});
        assert_eq!(
            review(
                State(fixture.state.clone()),
                fixture.headers.clone(),
                AxumPath(uuid::Uuid::new_v4().to_string())
            )
            .await
            .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            receipt(
                State(fixture.state),
                fixture.headers,
                AxumPath(uuid::Uuid::new_v4().to_string())
            )
            .await
            .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let fixture = replies(|service| {
            service.receipt.as_mut().unwrap().response.decision =
                opaque_core::scope_review::Decision::Reject
        });
        let id = fixture.review.document.round_id.clone();
        assert_eq!(
            respond(
                State(fixture.state),
                fixture.headers,
                AxumPath(id),
                Json(fixture.decision)
            )
            .await
            .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn scope_routes_reject_unverifiable_host_artifacts_and_missing_receipts() {
        let fixture = replies(|service| service.identity.broker_public_key = "f".repeat(64));
        let id = fixture.review.document.round_id.clone();
        assert_eq!(
            pending(State(fixture.state.clone()), fixture.headers.clone())
                .await
                .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            review(
                State(fixture.state.clone()),
                fixture.headers.clone(),
                AxumPath(id.clone())
            )
            .await
            .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            receipt(
                State(fixture.state.clone()),
                fixture.headers.clone(),
                AxumPath(id.clone())
            )
            .await
            .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            respond(
                State(fixture.state),
                fixture.headers,
                AxumPath(id),
                Json(fixture.decision)
            )
            .await
            .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let fixture = replies(|service| service.receipt = None);
        assert_eq!(
            receipt(
                State(fixture.state),
                fixture.headers,
                AxumPath(fixture.review.document.round_id)
            )
            .await
            .unwrap_err(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn key_routes_validate_live_enrollment_and_return_only_fixed_host_error_statuses() {
        for (error, expected) in [
            (
                ScopeReviewServiceError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (ScopeReviewServiceError::NotFound, StatusCode::NOT_FOUND),
            (ScopeReviewServiceError::Forbidden, StatusCode::FORBIDDEN),
            (ScopeReviewServiceError::Conflict, StatusCode::CONFLICT),
        ] {
            let fixture = replies(|service| service.error = Some(error));
            assert_eq!(
                key(State(fixture.state), fixture.headers)
                    .await
                    .unwrap_err(),
                expected
            );
        }
        for change in 0..2 {
            let fixture = replies(|service| match change {
                0 => service.identity.device_id = "other-device".into(),
                _ => service.identity.reviewer_public_key = "f".repeat(64),
            });
            assert_eq!(
                key(State(fixture.state), fixture.headers)
                    .await
                    .unwrap_err(),
                StatusCode::FORBIDDEN
            );
        }
        let mut fixture = replies(|_| {});
        fixture
            .headers
            .append("x-opaque-device", "second-device".parse().unwrap());
        assert_eq!(
            key(State(fixture.state), fixture.headers)
                .await
                .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        let fixture = replies(|_| {});
        let device = fixture.headers["x-opaque-device"].to_str().unwrap();
        fixture.state.pairing.revoke_device(device).unwrap();
        assert_eq!(
            key(State(fixture.state), fixture.headers)
                .await
                .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
    }
}
