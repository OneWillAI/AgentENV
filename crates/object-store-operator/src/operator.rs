use std::future::Future;
use std::time::Duration;

use anyhow::Context;
use http::header::{AUTHORIZATION, CONTENT_LENGTH};
use http::{Method, Request, Response};
use opendal::layers::{HttpClientLayer, RetryLayer, TimeoutLayer};
use opendal::raw::{HttpBody, HttpClient, HttpFetch};
use opendal::services::S3;
use opendal::Buffer;
use thiserror::Error;

use crate::auth::{CachedBearerTokenSource, CachedCredentialSource, ResolvedCredential};
use crate::{OpenDalError, OpenDalErrorKind, OpenDalResult, Operator};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_MAX_RETRIES: usize = 3;

pub type ObjectStoreOperatorResult<T> = std::result::Result<T, ObjectStoreOperatorError>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AddressingStyle {
    Virtual,
    Path,
}

impl AddressingStyle {
    pub fn uses_virtual_host_style(&self) -> bool {
        matches!(self, Self::Virtual)
    }
}

#[derive(Clone, Debug)]
pub struct ObjectStoreOperatorConfig {
    pub bucket: String,
    pub endpoint: String,
    pub region: String,
    pub addressing_style: AddressingStyle,
    pub timeout: Option<Duration>,
    pub max_retries: Option<usize>,
    pub bearer_tokens: Option<std::sync::Arc<CachedBearerTokenSource>>,
}

#[derive(Clone, Debug)]
pub struct OperatorWithCredential {
    operator: Operator,
    credential: Option<ResolvedCredential>,
}

impl OperatorWithCredential {
    pub fn new(operator: Operator, credential: Option<ResolvedCredential>) -> Self {
        Self {
            operator,
            credential,
        }
    }

    pub fn operator(&self) -> &Operator {
        &self.operator
    }

    pub fn credential(&self) -> Option<&ResolvedCredential> {
        self.credential.as_ref()
    }
}

#[derive(Debug, Error)]
pub enum ObjectStoreOperatorError {
    #[error(transparent)]
    OpenDal(#[from] OpenDalError),
    #[error("credential refresh failed")]
    CredentialRefresh(#[source] anyhow::Error),
    #[error("operator build failed")]
    OperatorBuild(#[source] anyhow::Error),
}

/// GCS's S3-compatible XML API rejects an empty multipart-initiation POST
/// unless it explicitly carries `Content-Length: 0`. OpenDAL represents an
/// empty request body by omitting the body entirely, so reqwest otherwise
/// omits that header. Add it at the transport boundary, after request signing;
/// content-length is not part of OpenDAL's signed-header set.
#[derive(Clone, Debug, Default)]
struct S3CompatibleHttpClient {
    inner: reqwest::Client,
    bearer_tokens: Option<std::sync::Arc<CachedBearerTokenSource>>,
}

impl HttpFetch for S3CompatibleHttpClient {
    async fn fetch(&self, mut request: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        if let Some(tokens) = self.bearer_tokens.as_ref() {
            let token = tokens.current().await.map_err(|err| {
                OpenDalError::new(
                    OpenDalErrorKind::Unexpected,
                    "fetch object-store OAuth bearer token",
                )
                .set_source(err)
            })?;
            let value = http::HeaderValue::from_str(&format!("Bearer {}", token.access_token))
                .map_err(|err| {
                    OpenDalError::new(
                        OpenDalErrorKind::Unexpected,
                        "construct object-store OAuth Authorization header",
                    )
                    .set_source(err)
                })?;
            request.headers_mut().insert(AUTHORIZATION, value);
        }
        let is_multipart_init = request.method() == Method::POST
            && request.body().is_empty()
            && request.uri().query().is_some_and(|query| {
                query
                    .split('&')
                    .any(|parameter| parameter == "uploads" || parameter.starts_with("uploads="))
            });
        if is_multipart_init && !request.headers().contains_key(CONTENT_LENGTH) {
            request
                .headers_mut()
                .insert(CONTENT_LENGTH, http::HeaderValue::from_static("0"));
        }

        self.inner.fetch(request).await
    }
}

pub fn build_object_store_operator(
    config: &ObjectStoreOperatorConfig,
    credential: Option<&ResolvedCredential>,
) -> ObjectStoreOperatorResult<Operator> {
    let mut builder = S3::default()
        .bucket(&config.bucket)
        .endpoint(&config.endpoint)
        .region(&config.region);

    if config.addressing_style.uses_virtual_host_style() {
        builder = builder.enable_virtual_host_style();
    }

    if config.bearer_tokens.is_some() {
        // OAuth owns authentication for this transport. Prevent OpenDAL's S3
        // signer from probing AWS environment/profile/IMDS credentials before
        // the request reaches the Bearer-token injecting HTTP client.
        builder = builder
            .disable_config_load()
            .disable_ec2_metadata()
            .allow_anonymous();
    } else if let Some(credential) = credential {
        builder = builder.access_key_id(&credential.access_key_id);
        builder = builder.secret_access_key(&credential.secret_access_key);
        if let Some(token) = credential.security_token.as_deref() {
            builder = builder.session_token(token);
        }
    } else {
        builder = builder.allow_anonymous();
    }

    let timeout = config.timeout.unwrap_or(DEFAULT_TIMEOUT);
    let max_retries = config.max_retries.unwrap_or(DEFAULT_MAX_RETRIES);
    let operator = Operator::new(builder)
        .context("build OpenDAL object-store operator")
        .map_err(ObjectStoreOperatorError::OperatorBuild)?
        .finish()
        .layer(HttpClientLayer::new(HttpClient::with(
            S3CompatibleHttpClient {
                inner: reqwest::Client::new(),
                bearer_tokens: config.bearer_tokens.clone(),
            },
        )))
        .layer(
            TimeoutLayer::new()
                .with_timeout(timeout)
                .with_io_timeout(timeout),
        )
        .layer(RetryLayer::new().with_max_times(max_retries));

    Ok(operator)
}

pub async fn run_with_refresh<T, F, Fut>(
    current: &OperatorWithCredential,
    credentials: Option<&CachedCredentialSource>,
    config: &ObjectStoreOperatorConfig,
    op: F,
) -> ObjectStoreOperatorResult<(T, Option<OperatorWithCredential>)>
where
    F: Fn(Operator) -> Fut,
    Fut: Future<Output = OpenDalResult<T>>,
{
    match op(current.operator().clone()).await {
        Ok(value) => Ok((value, None)),
        Err(err) if err.kind() == OpenDalErrorKind::PermissionDenied => {
            // Only permission-denied responses trigger credential refresh.
            // This matches the backends we currently target, including Aliyun
            // OSS, where expired credentials surface as 403-style failures.
            // Other authentication errors are treated as terminal until we
            // explicitly broaden the retry contract.
            let Some(credentials) = credentials else {
                return Err(ObjectStoreOperatorError::OpenDal(err));
            };
            let Some(previous) = current.credential() else {
                return Err(ObjectStoreOperatorError::OpenDal(err));
            };
            let Some(refreshed) = credentials
                .force_refresh(previous)
                .await
                .map_err(ObjectStoreOperatorError::CredentialRefresh)?
            else {
                return Err(ObjectStoreOperatorError::OpenDal(err));
            };
            let operator = build_object_store_operator(config, Some(&refreshed))?;
            let value = op(operator.clone()).await?;
            Ok((
                value,
                Some(OperatorWithCredential::new(operator, Some(refreshed))),
            ))
        }
        Err(err) => Err(ObjectStoreOperatorError::OpenDal(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressingStyle, S3CompatibleHttpClient};
    use crate::CachedBearerTokenSource;
    use opendal::raw::HttpFetch;
    use opendal::Buffer;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{mpsc, Arc};

    fn serve_once(response_body: &'static str) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test HTTP server");
        let address = listener.local_addr().expect("test HTTP address");
        let (requests_tx, requests_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            requests_tx
                .send(String::from_utf8(request).expect("request UTF-8"))
                .expect("capture request");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            )
            .expect("write response");
        });
        (format!("http://{address}"), requests_rx)
    }

    #[test]
    fn addressing_style_maps_to_expected_s3_modes() {
        assert!(AddressingStyle::Virtual.uses_virtual_host_style());
        assert!(!AddressingStyle::Path.uses_virtual_host_style());
    }

    #[tokio::test]
    async fn transport_injects_google_oauth_into_multipart_init() {
        let token_payload =
            r#"{"access_token":"oauth-token","expires_in":3600,"token_type":"Bearer"}"#;
        let (metadata_endpoint, _metadata_requests) = serve_once(token_payload);
        let (object_endpoint, object_requests) = serve_once("");
        let client = S3CompatibleHttpClient {
            inner: reqwest::Client::new(),
            bearer_tokens: Some(Arc::new(
                CachedBearerTokenSource::google_compute_engine_with_endpoint(metadata_endpoint),
            )),
        };
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("{object_endpoint}/bucket/layer?uploads"))
            .body(Buffer::new())
            .expect("build object request");

        client.fetch(request).await.expect("fetch object");
        let request = object_requests.recv().expect("object request");
        assert!(request.contains("authorization: Bearer oauth-token"));
        assert!(request.contains("content-length: 0"));
    }
}
