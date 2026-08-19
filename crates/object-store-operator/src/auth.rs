use std::fmt;
use std::process::Stdio;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::process::Command;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;

pub const CREDENTIAL_REFRESH_BUFFER: Duration = Duration::from_secs(120);
pub const CREDENTIAL_PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
pub const GOOGLE_METADATA_TOKEN_ENDPOINT: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialSource {
    Anonymous,
    Static(ResolvedCredential),
    Process { command: String },
    GoogleServiceAccount,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedCredential {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub security_token: Option<String>,
    pub expires_at: Option<SystemTime>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedBearerToken {
    pub access_token: String,
    pub expires_at: SystemTime,
}

#[derive(Debug, Deserialize)]
struct GoogleMetadataTokenResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
}

pub struct CachedBearerTokenSource {
    endpoint: String,
    client: reqwest::Client,
    cached: RwLock<Option<ResolvedBearerToken>>,
    refresh_lock: Mutex<()>,
}

#[derive(Debug, Clone, Copy)]
pub struct CredentialFields<'a> {
    pub access_key_id: Option<&'a str>,
    pub secret_access_key: Option<&'a str>,
    pub security_token: Option<&'a str>,
    pub credential_process: Option<&'a str>,
    pub google_service_account: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CredentialSourceOptions<'a> {
    pub scope: &'a str,
    pub allow_anonymous: bool,
    pub required_access_key_id_label: &'a str,
    pub required_secret_access_key_label: &'a str,
}

#[derive(Debug, Deserialize)]
struct ProcessCredentialOutput {
    #[serde(alias = "AccessKeyId", alias = "accessKeyId", alias = "access_key_id")]
    access_key_id: String,
    #[serde(
        alias = "AccessKeySecret",
        alias = "SecretAccessKey",
        alias = "accessKeySecret",
        alias = "secretAccessKey",
        alias = "secret_access_key",
        alias = "access_key_secret"
    )]
    access_key_secret: String,
    #[serde(
        default,
        alias = "SecurityToken",
        alias = "SessionToken",
        alias = "securityToken",
        alias = "security_token",
        alias = "stsToken",
        alias = "sts_token"
    )]
    security_token: Option<String>,
    #[serde(
        default,
        alias = "Expiration",
        alias = "expiration",
        alias = "expiresAt",
        alias = "expires_at"
    )]
    expiration: Option<String>,
}

impl fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "security_token",
                &self.security_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl ResolvedCredential {
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        security_token: Option<String>,
        expires_at: Option<SystemTime>,
    ) -> Result<Self> {
        if access_key_id.trim().is_empty() {
            bail!("resolved object-store credential is missing access_key_id");
        }
        if secret_access_key.trim().is_empty() {
            bail!("resolved object-store credential is missing access_key_secret");
        }

        Ok(Self {
            access_key_id,
            secret_access_key,
            security_token,
            expires_at,
        })
    }

    pub fn should_refresh(&self, now: SystemTime) -> bool {
        let Some(expires_at) = self.expires_at else {
            return false;
        };
        let refresh_at = now.checked_add(CREDENTIAL_REFRESH_BUFFER).unwrap_or(now);
        expires_at <= refresh_at
    }
}

impl fmt::Debug for ResolvedBearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedBearerToken")
            .field("access_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl ResolvedBearerToken {
    fn should_refresh(&self, now: SystemTime) -> bool {
        let refresh_at = now.checked_add(CREDENTIAL_REFRESH_BUFFER).unwrap_or(now);
        self.expires_at <= refresh_at
    }
}

impl CachedBearerTokenSource {
    pub fn google_compute_engine() -> Self {
        Self::google_compute_engine_with_endpoint(GOOGLE_METADATA_TOKEN_ENDPOINT)
    }

    pub fn google_compute_engine_with_endpoint(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: reqwest::Client::new(),
            cached: RwLock::new(None),
            refresh_lock: Mutex::new(()),
        }
    }

    pub async fn current(&self) -> Result<ResolvedBearerToken> {
        {
            let cached = self.cached.read().await;
            if let Some(token) = cached.as_ref() {
                if !token.should_refresh(SystemTime::now()) {
                    return Ok(token.clone());
                }
            }
        }

        let _guard = self.refresh_lock.lock().await;
        {
            let cached = self.cached.read().await;
            if let Some(token) = cached.as_ref() {
                if !token.should_refresh(SystemTime::now()) {
                    return Ok(token.clone());
                }
            }
        }

        let token = self.fetch_google_metadata_token().await?;
        *self.cached.write().await = Some(token.clone());
        Ok(token)
    }

    async fn fetch_google_metadata_token(&self) -> Result<ResolvedBearerToken> {
        let response = self
            .client
            .get(&self.endpoint)
            .header("Metadata-Flavor", "Google")
            .timeout(CREDENTIAL_PROCESS_TIMEOUT)
            .send()
            .await
            .context("fetch Google service-account OAuth token from metadata server")?
            .error_for_status()
            .context("Google metadata token endpoint returned an error")?;
        let payload: GoogleMetadataTokenResponse = response
            .json()
            .await
            .context("parse Google metadata token response")?;
        if !payload.token_type.eq_ignore_ascii_case("bearer") {
            bail!("Google metadata token response has unsupported token_type");
        }
        let access_token = payload.access_token.trim().to_string();
        if access_token.is_empty() {
            bail!("Google metadata token response has an empty access_token");
        }
        if payload.expires_in == 0 {
            bail!("Google metadata token response has a zero expires_in");
        }
        let expires_at = SystemTime::now()
            .checked_add(Duration::from_secs(payload.expires_in))
            .context("Google metadata token expiration overflows system time")?;
        Ok(ResolvedBearerToken {
            access_token,
            expires_at,
        })
    }
}

impl fmt::Debug for CachedBearerTokenSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedBearerTokenSource")
            .field("kind", &"google_compute_engine")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

pub fn credential_source_from_fields(
    fields: CredentialFields<'_>,
    options: CredentialSourceOptions<'_>,
) -> Result<CredentialSource> {
    let access_key_id = normalized_credential(fields.access_key_id);
    let secret_access_key = normalized_credential(fields.secret_access_key);
    let security_token = normalized_credential(fields.security_token);

    if fields.google_service_account {
        if access_key_id.is_some()
            || secret_access_key.is_some()
            || security_token.is_some()
            || normalized_credential(fields.credential_process).is_some()
        {
            bail!(
                "{} google_service_account cannot be combined with static credentials or credential_process",
                options.scope
            );
        }
        return Ok(CredentialSource::GoogleServiceAccount);
    }

    if let Some(command) = normalized_credential(fields.credential_process) {
        if access_key_id.is_some() || secret_access_key.is_some() || security_token.is_some() {
            bail!(
                "{} credential_process cannot be combined with access_key_id, secret_access_key, or security_token",
                options.scope
            );
        }
        return Ok(CredentialSource::Process {
            command: command.to_string(),
        });
    }

    match (access_key_id, secret_access_key) {
        (None, None) => {
            if security_token.is_some() {
                bail!(
                    "{} security_token requires access_key_id and secret_access_key",
                    options.scope
                );
            }
            if options.allow_anonymous {
                Ok(CredentialSource::Anonymous)
            } else {
                Err(anyhow!(
                    "{} is required",
                    options.required_access_key_id_label
                ))
            }
        }
        (Some(access_key_id), Some(secret_access_key)) => {
            Ok(CredentialSource::Static(ResolvedCredential::new(
                access_key_id.to_string(),
                secret_access_key.to_string(),
                security_token.map(str::to_string),
                None,
            )?))
        }
        (None, Some(_)) => {
            if options.allow_anonymous {
                bail!(
                    "{} access_key_id and secret_access_key must be set together",
                    options.scope
                );
            }
            Err(anyhow!(
                "{} is required",
                options.required_access_key_id_label
            ))
        }
        (Some(_), None) => {
            if options.allow_anonymous {
                bail!(
                    "{} access_key_id and secret_access_key must be set together",
                    options.scope
                );
            }
            Err(anyhow!(
                "{} is required",
                options.required_secret_access_key_label
            ))
        }
    }
}

pub async fn resolve_credential_from_process(command: &str) -> Result<ResolvedCredential> {
    let argv = split_credential_process_command(command)?;
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| anyhow!("object-store credential_process is empty"))?;
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawn object-store credential_process '{command}'"))?;
    let output = timeout(CREDENTIAL_PROCESS_TIMEOUT, child.wait_with_output())
        .await
        .with_context(|| {
            format!(
                "timed out after {:?} executing object-store credential_process '{command}'",
                CREDENTIAL_PROCESS_TIMEOUT
            )
        })?
        .with_context(|| format!("execute object-store credential_process '{command}'"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "object-store credential_process exited with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8(output.stdout)
        .context("object-store credential_process stdout is not valid UTF-8")?;
    let payload: ProcessCredentialOutput = serde_json::from_str(stdout.trim())
        .context("parse object-store credential_process JSON failed")?;

    let expires_at = parse_expiration(payload.expiration.as_deref())?;
    let security_token = payload.security_token.and_then(|value| {
        let trimmed = value.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    });

    ResolvedCredential::new(
        payload.access_key_id.trim().to_string(),
        payload.access_key_secret.trim().to_string(),
        security_token,
        expires_at,
    )
}

pub fn normalized_credential(value: Option<&str>) -> Option<&str> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then_some(trimmed)
    })
}

fn split_credential_process_command(command: &str) -> Result<Vec<String>> {
    // This parser intentionally supports only argv-style tokenization.
    // It does not perform shell expansion such as `$VAR`, backticks, pipes,
    // or command substitution.
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut quote = None;

    while let Some(ch) = chars.next() {
        match quote {
            Some(delimiter) if ch == delimiter => {
                quote = None;
            }
            Some('"') if ch == '\\' => {
                let escaped = chars.next().ok_or_else(|| {
                    anyhow!("object-store credential_process ends with a trailing escape")
                })?;
                current.push(escaped);
            }
            Some(_) => current.push(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            None if ch == '\'' || ch == '"' => {
                quote = Some(ch);
            }
            None if ch == '\\' => {
                let escaped = chars.next().ok_or_else(|| {
                    anyhow!("object-store credential_process ends with a trailing escape")
                })?;
                current.push(escaped);
            }
            None => current.push(ch),
        }
    }

    if quote.is_some() {
        bail!("object-store credential_process has an unterminated quote");
    }
    if !current.is_empty() {
        args.push(current);
    }
    if args.is_empty() {
        bail!("object-store credential_process is empty");
    }

    Ok(args)
}

pub fn parse_expiration(value: Option<&str>) -> Result<Option<SystemTime>> {
    let Some(value) = normalized_credential(value) else {
        return Ok(None);
    };

    let expires_at = DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("parse credential_process expiration '{value}'"))?
        .with_timezone(&Utc);
    Ok(Some(expires_at.into()))
}

pub struct CachedCredentialSource {
    source: CredentialSource,
    cached: RwLock<Option<ResolvedCredential>>,
    refresh_lock: Mutex<()>,
}

impl CachedCredentialSource {
    pub fn new(source: CredentialSource) -> Self {
        Self {
            source,
            cached: RwLock::new(None),
            refresh_lock: Mutex::new(()),
        }
    }

    pub async fn current(&self) -> Result<Option<ResolvedCredential>> {
        match &self.source {
            CredentialSource::Anonymous => Ok(None),
            CredentialSource::Static(credential) => Ok(Some(credential.clone())),
            CredentialSource::GoogleServiceAccount => Ok(None),
            CredentialSource::Process { command } => {
                {
                    let cached = self.cached.read().await;
                    if let Some(credential) = cached.as_ref() {
                        if !credential.should_refresh(SystemTime::now()) {
                            return Ok(Some(credential.clone()));
                        }
                    }
                }

                let _guard = self.refresh_lock.lock().await;
                {
                    let cached = self.cached.read().await;
                    if let Some(credential) = cached.as_ref() {
                        if !credential.should_refresh(SystemTime::now()) {
                            return Ok(Some(credential.clone()));
                        }
                    }
                }

                let refreshed = resolve_credential_from_process(command).await?;
                *self.cached.write().await = Some(refreshed.clone());
                Ok(Some(refreshed))
            }
        }
    }

    pub async fn force_refresh(
        &self,
        previous: &ResolvedCredential,
    ) -> Result<Option<ResolvedCredential>> {
        match &self.source {
            CredentialSource::Anonymous => Ok(None),
            CredentialSource::Static(credential) => Ok(Some(credential.clone())),
            CredentialSource::GoogleServiceAccount => Ok(None),
            CredentialSource::Process { command } => {
                let _guard = self.refresh_lock.lock().await;
                {
                    let cached = self.cached.read().await;
                    if let Some(credential) = cached.as_ref() {
                        if credential != previous {
                            return Ok(Some(credential.clone()));
                        }
                    }
                }

                let refreshed = resolve_credential_from_process(command).await?;
                *self.cached.write().await = Some(refreshed.clone());
                Ok(Some(refreshed))
            }
        }
    }

    pub fn supports_refresh(&self) -> bool {
        matches!(self.source, CredentialSource::Process { .. })
    }
}

impl fmt::Debug for CachedCredentialSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedCredentialSource")
            .field(
                "kind",
                &match &self.source {
                    CredentialSource::Anonymous => "anonymous",
                    CredentialSource::Static(_) => "static",
                    CredentialSource::Process { .. } => "process",
                    CredentialSource::GoogleServiceAccount => "google_service_account",
                },
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn serve_metadata_tokens(
        payloads: Vec<&'static str>,
    ) -> (String, mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind metadata test server");
        let address = listener.local_addr().expect("metadata test address");
        let (requests_tx, requests_rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            for payload in payloads {
                let (mut stream, _) = listener.accept().expect("accept metadata request");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let read = stream.read(&mut buffer).expect("read metadata request");
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
                    .expect("capture metadata request");
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                )
                .expect("write metadata response");
            }
        });
        (format!("http://{address}/token"), requests_rx, handle)
    }

    #[test]
    fn mixed_process_and_static_credentials_are_rejected() {
        let err = credential_source_from_fields(
            CredentialFields {
                access_key_id: Some("ak"),
                secret_access_key: Some("sk"),
                security_token: None,
                credential_process: Some("echo '{}'"),
                google_service_account: false,
            },
            CredentialSourceOptions {
                scope: "backend.oss",
                allow_anonymous: false,
                required_access_key_id_label: "backend.oss.access_key_id",
                required_secret_access_key_label: "backend.oss.access_key_secret",
            },
        )
        .expect_err("mixed source should fail");

        assert!(err.to_string().contains("credential_process"));
    }

    #[test]
    fn google_service_account_rejects_other_credentials() {
        let err = credential_source_from_fields(
            CredentialFields {
                access_key_id: Some("ak"),
                secret_access_key: Some("sk"),
                security_token: None,
                credential_process: None,
                google_service_account: true,
            },
            CredentialSourceOptions {
                scope: "backend.oss",
                allow_anonymous: false,
                required_access_key_id_label: "backend.oss.access_key_id",
                required_secret_access_key_label: "backend.oss.access_key_secret",
            },
        )
        .expect_err("mixed Google and static credentials should fail");

        assert!(err.to_string().contains("google_service_account"));
    }

    #[tokio::test]
    async fn google_metadata_tokens_are_injected_from_metadata_and_cached() {
        let (endpoint, requests, server) = serve_metadata_tokens(vec![
            r#"{"access_token":"token-one","expires_in":3600,"token_type":"Bearer"}"#,
        ]);
        let source = CachedBearerTokenSource::google_compute_engine_with_endpoint(endpoint);

        assert_eq!(
            source.current().await.expect("first token").access_token,
            "token-one"
        );
        assert_eq!(
            source.current().await.expect("cached token").access_token,
            "token-one"
        );
        let request = requests.recv().expect("metadata request");
        assert!(request
            .to_ascii_lowercase()
            .contains("metadata-flavor: google"));
        server.join().expect("metadata server");
    }

    #[tokio::test]
    async fn google_metadata_token_refreshes_before_expiration() {
        let (endpoint, _requests, server) = serve_metadata_tokens(vec![
            r#"{"access_token":"token-one","expires_in":1,"token_type":"Bearer"}"#,
            r#"{"access_token":"token-two","expires_in":3600,"token_type":"Bearer"}"#,
        ]);
        let source = CachedBearerTokenSource::google_compute_engine_with_endpoint(endpoint);

        assert_eq!(
            source.current().await.expect("first token").access_token,
            "token-one"
        );
        assert_eq!(
            source
                .current()
                .await
                .expect("refreshed token")
                .access_token,
            "token-two"
        );
        server.join().expect("metadata server");
    }

    #[test]
    fn expiration_inside_refresh_window_requests_refresh() {
        let credential = ResolvedCredential::new(
            "ak".to_string(),
            "sk".to_string(),
            None,
            Some(SystemTime::now() + Duration::from_secs(30)),
        )
        .expect("credential");

        assert!(credential.should_refresh(SystemTime::now()));
    }

    #[test]
    fn parse_expiration_accepts_rfc3339() {
        let expires_at = parse_expiration(Some("2030-01-02T03:04:05Z"))
            .expect("parse expiration")
            .expect("expiration should exist");
        assert!(expires_at > SystemTime::UNIX_EPOCH);
    }

    #[tokio::test]
    async fn resolve_credential_from_process_parses_payload() {
        let credential = resolve_credential_from_process(
            "printf '%s' '{\"AccessKeyId\":\"ak\",\"AccessKeySecret\":\"sk\",\"SecurityToken\":\"token\",\"Expiration\":\"2035-01-02T03:04:05Z\"}'",
        )
        .await
        .expect("resolve credential");

        assert_eq!(credential.access_key_id, "ak");
        assert_eq!(credential.secret_access_key, "sk");
        assert_eq!(credential.security_token.as_deref(), Some("token"));
        assert!(credential.expires_at.is_some());
    }

    #[tokio::test]
    async fn resolve_credential_from_process_accepts_aws_payload() {
        let credential = resolve_credential_from_process(
            "printf '%s' '{\"Version\":1,\"AccessKeyId\":\"ak\",\"SecretAccessKey\":\"sk\",\"SessionToken\":\"token\",\"Expiration\":\"2035-01-02T03:04:05Z\"}'",
        )
        .await
        .expect("resolve aws credential_process payload");

        assert_eq!(credential.access_key_id, "ak");
        assert_eq!(credential.secret_access_key, "sk");
        assert_eq!(credential.security_token.as_deref(), Some("token"));
        assert!(credential.expires_at.is_some());
    }

    #[test]
    fn split_credential_process_command_rejects_unterminated_quote() {
        let err = split_credential_process_command("echo 'unterminated")
            .expect_err("unterminated quote should fail");
        assert!(err.to_string().contains("unterminated quote"));
    }
}
