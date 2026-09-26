use anyhow::Result;
use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use aws_sdk_s3::config::Credentials;
use aws_sdk_s3::Client as S3Client;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

pub const MINIO_USER: &str = "minioadmin";
pub const MINIO_PASS: &str = "minioadmin";
pub const REGION: &str = "us-east-1";
pub const BUCKET: &str = "test-bucket";

// The minio/minio repository on Docker Hub was removed; MinIO now publishes to
// quay.io. Pin a release tag so tests do not drift with `latest`.
const MINIO_IMAGE: &str = "quay.io/minio/minio";
const MINIO_TAG: &str = "RELEASE.2025-09-07T16-13-09Z";

pub struct MinioFixture {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub client: S3Client,
    _container: ContainerAsync<GenericImage>,
}

impl MinioFixture {
    pub async fn start() -> Result<Self> {
        // Current MinIO images print the startup banner (including the "API:"
        // line) to stderr, so readiness must watch stderr, not stdout.
        let container = GenericImage::new(MINIO_IMAGE, MINIO_TAG)
            .with_wait_for(WaitFor::message_on_stderr("API:"))
            .with_env_var("MINIO_ROOT_USER", MINIO_USER)
            .with_env_var("MINIO_ROOT_PASSWORD", MINIO_PASS)
            .with_env_var("MINIO_CONSOLE_ADDRESS", ":9001")
            .with_cmd(["server", "/data"])
            .start()
            .await?;
        let port = container.get_host_port_ipv4(9000).await?;
        let endpoint = format!("http://127.0.0.1:{port}");
        let client = build_s3_client(&endpoint).await;
        client.create_bucket().bucket(BUCKET).send().await?;

        Ok(Self {
            endpoint,
            bucket: BUCKET.to_string(),
            region: REGION.to_string(),
            client,
            _container: container,
        })
    }

    pub async fn object_exists(&self, key: &str) -> Result<bool> {
        let result = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await;
        Ok(result.is_ok())
    }

    pub fn object_url(&self, key: &str) -> String {
        format!(
            "s3://{}/{}?endpoint={}&region={}",
            self.bucket, key, self.endpoint, self.region
        )
    }
}

async fn build_s3_client(endpoint: &str) -> S3Client {
    let region_provider = RegionProviderChain::default_provider().or_else(REGION);
    let creds = Credentials::new(MINIO_USER, MINIO_PASS, None, None, "agentenv-tests");
    let shared_config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .endpoint_url(endpoint)
        .credentials_provider(creds)
        .load()
        .await;
    S3Client::new(&shared_config)
}
