//! GitHub Actions `workflow_dispatch` protocol shared by the bounded staging
//! task family and the scoped-authority runtime. Callers own credential
//! custody, TLS trust, policy, human approval, reservation and the durable
//! at-most-once dispatch claim; this module only speaks the fixed API shape.
use serde::Deserialize;

pub const API_VERSION: &str = "2026-03-10";
/// Typed read responses are small; anything larger is not the expected object.
pub const MAX_READ_BYTES: usize = 64 * 1024;

/// One dispatch target: `owner/repo`, a workflow file and a branch name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target<'a> {
    pub repository: &'a str,
    pub path: &'a str,
    pub git_ref: &'a str,
}
impl Target<'_> {
    pub fn validate(&self) -> Result<(), String> {
        opaque_core::release::validate_repository(self.repository)?;
        opaque_core::release::validate_workflow_path(self.path)?;
        opaque_core::release::validate_branch(self.git_ref)?;
        Ok(())
    }
    /// The last path component; `rsplit` always yields one, so this cannot fail.
    fn file_name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(self.path)
    }
}

/// Fixed headers every GitHub REST request carries.
pub fn headers(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    builder
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", API_VERSION)
        .header("user-agent", "opaqued")
}

/// `{base}/repos/{owner}/{repo}/{suffix...}` built from path segments, never
/// from string concatenation, so a component cannot introduce a separator.
pub fn repository_url(
    base: &reqwest::Url,
    repository: &str,
    suffix: &[&str],
) -> Result<reqwest::Url, String> {
    let (owner, repo) = repository
        .split_once('/')
        .ok_or("invalid repository identity")?;
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| "invalid GitHub API base")?;
        path.pop_if_empty()
            .extend(["repos", owner, repo])
            .extend(suffix.iter().copied());
    }
    Ok(url)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Workflow {
    pub id: u64,
    pub path: String,
    pub state: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Commit {
    pub sha: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Branch {
    pub name: String,
    pub protected: bool,
    pub commit: Commit,
}

async fn read<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: reqwest::Url,
    authorization: &reqwest::header::HeaderValue,
) -> Result<T, String> {
    let mut response = headers(http.get(url))
        .header(reqwest::header::AUTHORIZATION, authorization.clone())
        .send()
        .await
        .map_err(|_| "GitHub read unavailable")?;
    if response.status() != reqwest::StatusCode::OK
        || response
            .content_length()
            .is_some_and(|n| n > MAX_READ_BYTES as u64)
    {
        return Err("GitHub read unavailable".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "GitHub read unavailable")?
    {
        if bytes.len() + chunk.len() > MAX_READ_BYTES {
            return Err("GitHub response too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid GitHub response".into())
}

/// `GET /repos/{owner}/{repo}/actions/workflows/{file}`; the returned path must
/// name the requested file and the workflow must be active.
pub async fn read_workflow(
    http: &reqwest::Client,
    base: &reqwest::Url,
    target: &Target<'_>,
    authorization: &reqwest::header::HeaderValue,
) -> Result<Workflow, String> {
    target.validate()?;
    let url = repository_url(
        base,
        target.repository,
        &["actions", "workflows", target.file_name()],
    )?;
    let workflow: Workflow = read(http, url, authorization).await?;
    if workflow.id == 0 || workflow.path != target.path || workflow.state != "active" {
        return Err("GitHub workflow mismatch or inactive".into());
    }
    Ok(workflow)
}

/// `GET /repos/{owner}/{repo}/branches/{ref}`; the head commit is the version
/// a reviewer sees. GitHub does not enforce it as a dispatch precondition.
pub async fn read_branch(
    http: &reqwest::Client,
    base: &reqwest::Url,
    target: &Target<'_>,
    authorization: &reqwest::header::HeaderValue,
) -> Result<Branch, String> {
    target.validate()?;
    let url = repository_url(base, target.repository, &["branches", target.git_ref])?;
    let branch: Branch = read(http, url, authorization).await?;
    if branch.name != target.git_ref
        || branch.commit.sha.len() != 40
        || !branch
            .commit
            .sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("GitHub branch mismatch".into());
    }
    Ok(branch)
}

/// `workflow_dispatch` accepts a branch OR tag name. Refuse a name that also
/// exists as a tag instead of assuming which one GitHub selects.
pub async fn tag_absent(
    http: &reqwest::Client,
    base: &reqwest::Url,
    target: &Target<'_>,
    authorization: &reqwest::header::HeaderValue,
) -> Result<(), String> {
    target.validate()?;
    let url = repository_url(
        base,
        target.repository,
        &["git", "ref", "tags", target.git_ref],
    )?;
    let response = headers(http.get(url))
        .header(reqwest::header::AUTHORIZATION, authorization.clone())
        .send()
        .await
        .map_err(|_| "GitHub read unavailable")?;
    if response.status() != reqwest::StatusCode::NOT_FOUND {
        return Err("branch name is ambiguous with a tag".into());
    }
    Ok(())
}

/// What one `POST .../dispatches` attempt established. `Accepted` is GitHub's
/// documented `204` acknowledgment (no run id), never workflow completion.
/// `Rejected` means GitHub validated and refused, so no run was created.
/// Everything else, including an undocumented `2xx`, a `408`, any `5xx` and a
/// transport failure, is `Unknown`: the request may or may not have dispatched,
/// and there is no idempotency key to make a second attempt safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acknowledgment {
    Accepted,
    Rejected,
    Unknown,
}
pub fn acknowledge(result: Result<reqwest::Response, reqwest::Error>) -> Acknowledgment {
    match result {
        Ok(response) if response.status().as_u16() == 204 => Acknowledgment::Accepted,
        Ok(response)
            if response.status().is_client_error() && response.status().as_u16() != 408 =>
        {
            Acknowledgment::Rejected
        }
        _ => Acknowledgment::Unknown,
    }
}

/// Exactly one `POST /repos/{owner}/{repo}/actions/workflows/{file}/dispatches`
/// with `{"ref": ref}` and no inputs. The caller must have consumed its dispatch
/// claim before calling; a returned `Unknown` must never be retried automatically.
pub async fn dispatch(
    http: &reqwest::Client,
    base: &reqwest::Url,
    target: &Target<'_>,
    authorization: &reqwest::header::HeaderValue,
) -> Acknowledgment {
    if target.validate().is_err() {
        return Acknowledgment::Unknown;
    }
    let Ok(url) = repository_url(
        base,
        target.repository,
        &["actions", "workflows", target.file_name(), "dispatches"],
    ) else {
        return Acknowledgment::Unknown;
    };
    acknowledge(
        headers(http.post(url))
            .header(reqwest::header::AUTHORIZATION, authorization.clone())
            .json(&serde_json::json!({"ref": target.git_ref}))
            .send()
            .await,
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TARGET: Target<'static> = Target {
        repository: "example-org/service",
        path: ".github/workflows/staging.yml",
        git_ref: "main",
    };
    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const WORKFLOW_ROUTE: &str = "/repos/example-org/service/actions/workflows/staging.yml";
    const BRANCH_ROUTE: &str = "/repos/example-org/service/branches/main";
    const TAG_ROUTE: &str = "/repos/example-org/service/git/ref/tags/main";

    fn http() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap()
    }
    fn auth() -> reqwest::header::HeaderValue {
        reqwest::header::HeaderValue::from_static("Bearer synthetic-token")
    }
    fn base(server: &MockServer) -> reqwest::Url {
        reqwest::Url::parse(&format!("{}/", server.uri())).unwrap()
    }
    /// Every mock requires the fixed GitHub headers and the caller's bearer token.
    async fn served(verb: &str, route: &str, response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method(verb))
            .and(path(route))
            .and(header("authorization", "Bearer synthetic-token"))
            .and(header("accept", "application/vnd.github+json"))
            .and(header("x-github-api-version", API_VERSION))
            .and(header("user-agent", "opaqued"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }
    async fn requests(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }
    fn workflow_body(id: u64, workflow_path: &str, state: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"id":id,"path":workflow_path,"state":state,"name":"Staging"}),
        )
    }
    fn branch_body(name: &str, sha: &str) -> ResponseTemplate {
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({"name":name,"protected":true,"commit":{"sha":sha}}))
    }
    /// A raw HTTP/1.1 server that streams an oversized chunked body with no
    /// declared length, so only the accumulating read bound can refuse it.
    async fn chunked_server(total: usize) -> reqwest::Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url =
            reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await;
            let _ = socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await;
            let chunk = vec![b'x'; 1000];
            for _ in 0..total.div_ceil(1000) {
                if socket
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await
                    .is_err()
                    || socket.write_all(&chunk).await.is_err()
                    || socket.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
            let _ = socket.write_all(b"0\r\n\r\n").await;
        });
        url
    }

    #[test]
    fn repository_urls_are_built_from_segments_and_refuse_unusable_inputs() {
        let github = reqwest::Url::parse("https://api.github.com/").unwrap();
        assert_eq!(
            repository_url(
                &github,
                TARGET.repository,
                &["actions", "workflows", TARGET.file_name(), "dispatches"]
            )
            .unwrap()
            .as_str(),
            "https://api.github.com/repos/example-org/service/actions/workflows/staging.yml/dispatches"
        );
        // A GitHub Enterprise Server base keeps its API prefix.
        let enterprise = reqwest::Url::parse("https://ghes.example.invalid/api/v3/").unwrap();
        assert_eq!(
            repository_url(
                &enterprise,
                TARGET.repository,
                &["branches", "release/2026-09"]
            )
            .unwrap()
            .as_str(),
            "https://ghes.example.invalid/api/v3/repos/example-org/service/branches/release%2F2026-09"
        );
        // A component can never introduce a path separator or a query.
        assert_eq!(
            repository_url(&github, TARGET.repository, &["branches", "main?x=1#y"])
                .unwrap()
                .as_str(),
            "https://api.github.com/repos/example-org/service/branches/main%3Fx=1%23y"
        );
        assert!(repository_url(&github, "service", &[]).is_err());
        let opaque_scheme = reqwest::Url::parse("mailto:ops@example.invalid").unwrap();
        assert!(repository_url(&opaque_scheme, TARGET.repository, &[]).is_err());
        assert!(TARGET.validate().is_ok());
        for (repository, workflow_path, git_ref) in [
            ("service", TARGET.path, TARGET.git_ref),
            (TARGET.repository, "staging.yml", TARGET.git_ref),
            (TARGET.repository, TARGET.path, "refs/heads/main"),
            (TARGET.repository, TARGET.path, SHA),
        ] {
            assert!(
                Target {
                    repository,
                    path: workflow_path,
                    git_ref,
                }
                .validate()
                .is_err(),
                "{repository} {workflow_path} {git_ref}"
            );
        }
    }

    #[tokio::test]
    async fn workflow_reads_require_an_active_workflow_at_the_exact_path() {
        let server = served(
            "GET",
            WORKFLOW_ROUTE,
            workflow_body(71, TARGET.path, "active"),
        )
        .await;
        let workflow = read_workflow(&http(), &base(&server), &TARGET, &auth())
            .await
            .unwrap();
        assert_eq!(workflow.id, 71);
        assert_eq!(workflow.path, TARGET.path);
        assert_eq!(requests(&server).await, 1);
        for (name, response) in [
            ("zero id", workflow_body(0, TARGET.path, "active")),
            (
                "other path",
                workflow_body(71, ".github/workflows/production.yml", "active"),
            ),
            (
                "disabled",
                workflow_body(71, TARGET.path, "disabled_manually"),
            ),
            ("not found", ResponseTemplate::new(404)),
            ("server error", ResponseTemplate::new(500)),
            (
                "malformed",
                ResponseTemplate::new(200).set_body_string("{\"id\":71,"),
            ),
            (
                "wrong shape",
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id":"71"})),
            ),
            (
                "declared oversize",
                ResponseTemplate::new(200).set_body_bytes(vec![b'{'; MAX_READ_BYTES + 1]),
            ),
        ] {
            let server = served("GET", WORKFLOW_ROUTE, response).await;
            assert!(
                read_workflow(&http(), &base(&server), &TARGET, &auth())
                    .await
                    .is_err(),
                "{name}"
            );
            assert_eq!(requests(&server).await, 1, "{name}");
        }
        // An invalid target never becomes a request.
        let server = served(
            "GET",
            WORKFLOW_ROUTE,
            workflow_body(71, TARGET.path, "active"),
        )
        .await;
        let invalid = Target {
            path: "staging.yml",
            ..TARGET
        };
        assert!(
            read_workflow(&http(), &base(&server), &invalid, &auth())
                .await
                .is_err()
        );
        assert_eq!(requests(&server).await, 0);
        // A body streamed without a declared length is refused at the read bound.
        let streamed = chunked_server(MAX_READ_BYTES + 4000).await;
        assert_eq!(
            read_workflow(&http(), &streamed, &TARGET, &auth())
                .await
                .unwrap_err(),
            "GitHub response too large"
        );
    }

    #[tokio::test]
    async fn branch_reads_require_the_named_branch_and_a_full_lowercase_hex_head() {
        let server = served("GET", BRANCH_ROUTE, branch_body("main", SHA)).await;
        let branch = read_branch(&http(), &base(&server), &TARGET, &auth())
            .await
            .unwrap();
        assert_eq!(branch.commit.sha, SHA);
        assert!(branch.protected);
        for (name, response) in [
            ("other branch", branch_body("develop", SHA)),
            ("short sha", branch_body("main", "abc123")),
            (
                "non hex sha",
                branch_body("main", &format!("{}g", &SHA[..39])),
            ),
            (
                "uppercase sha",
                branch_body("main", &SHA.to_ascii_uppercase()),
            ),
            (
                "missing protection field",
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"name":"main","commit":{"sha":SHA}})),
            ),
            ("not found", ResponseTemplate::new(404)),
            (
                "declared oversize",
                ResponseTemplate::new(200).set_body_bytes(vec![b'{'; MAX_READ_BYTES + 1]),
            ),
        ] {
            let server = served("GET", BRANCH_ROUTE, response).await;
            assert!(
                read_branch(&http(), &base(&server), &TARGET, &auth())
                    .await
                    .is_err(),
                "{name}"
            );
        }
        let invalid = Target {
            git_ref: "refs/heads/main",
            ..TARGET
        };
        let server = served("GET", BRANCH_ROUTE, branch_body("main", SHA)).await;
        assert!(
            read_branch(&http(), &base(&server), &invalid, &auth())
                .await
                .is_err()
        );
        assert_eq!(requests(&server).await, 0);
        // The read bound applies to a streamed branch body as well.
        let streamed = chunked_server(MAX_READ_BYTES + 4000).await;
        assert_eq!(
            read_branch(&http(), &streamed, &TARGET, &auth())
                .await
                .unwrap_err(),
            "GitHub response too large"
        );
    }

    #[tokio::test]
    async fn tag_check_accepts_only_a_definite_not_found() {
        let server = served("GET", TAG_ROUTE, ResponseTemplate::new(404)).await;
        tag_absent(&http(), &base(&server), &TARGET, &auth())
            .await
            .unwrap();
        for (name, response) in [
            (
                "tag exists",
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"ref":"refs/tags/main"})),
            ),
            ("forbidden", ResponseTemplate::new(403)),
            ("server error", ResponseTemplate::new(500)),
        ] {
            let server = served("GET", TAG_ROUTE, response).await;
            assert!(
                tag_absent(&http(), &base(&server), &TARGET, &auth())
                    .await
                    .is_err(),
                "{name}"
            );
        }
        // A closed port is uncertainty, never absence.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed =
            reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        drop(listener);
        assert!(
            tag_absent(&http(), &closed, &TARGET, &auth())
                .await
                .is_err()
        );
        let invalid = Target {
            repository: "service",
            ..TARGET
        };
        let server = served("GET", TAG_ROUTE, ResponseTemplate::new(404)).await;
        assert!(
            tag_absent(&http(), &base(&server), &invalid, &auth())
                .await
                .is_err()
        );
        assert_eq!(requests(&server).await, 0);
    }

    #[tokio::test]
    async fn dispatch_sends_one_fixed_body_and_maps_only_204_to_accepted() {
        for (status, expected) in [
            (204, Acknowledgment::Accepted),
            (200, Acknowledgment::Unknown),
            (201, Acknowledgment::Unknown),
            (202, Acknowledgment::Unknown),
            (302, Acknowledgment::Unknown),
            (400, Acknowledgment::Rejected),
            (401, Acknowledgment::Rejected),
            (403, Acknowledgment::Rejected),
            (404, Acknowledgment::Rejected),
            (408, Acknowledgment::Unknown),
            (422, Acknowledgment::Rejected),
            (429, Acknowledgment::Rejected),
            (500, Acknowledgment::Unknown),
            (502, Acknowledgment::Unknown),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(format!("{WORKFLOW_ROUTE}/dispatches")))
                .and(header("authorization", "Bearer synthetic-token"))
                .and(header("x-github-api-version", API_VERSION))
                .and(body_json(serde_json::json!({"ref":"main"})))
                .respond_with(ResponseTemplate::new(status))
                .expect(1)
                .mount(&server)
                .await;
            assert_eq!(
                dispatch(&http(), &base(&server), &TARGET, &auth()).await,
                expected,
                "{status}"
            );
            assert_eq!(requests(&server).await, 1, "{status}");
        }
        // Transport failure before any acknowledgment is Unknown.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed =
            reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        drop(listener);
        assert_eq!(
            dispatch(&http(), &closed, &TARGET, &auth()).await,
            Acknowledgment::Unknown
        );
        // An invalid target or an unusable base never becomes a POST.
        let server = served("POST", WORKFLOW_ROUTE, ResponseTemplate::new(204)).await;
        let invalid = Target {
            git_ref: "main..feature",
            ..TARGET
        };
        assert_eq!(
            dispatch(&http(), &base(&server), &invalid, &auth()).await,
            Acknowledgment::Unknown
        );
        let opaque_scheme = reqwest::Url::parse("mailto:ops@example.invalid").unwrap();
        assert_eq!(
            dispatch(&http(), &opaque_scheme, &TARGET, &auth()).await,
            Acknowledgment::Unknown
        );
        assert_eq!(requests(&server).await, 0);
    }
}
