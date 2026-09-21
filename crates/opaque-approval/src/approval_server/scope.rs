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
}
