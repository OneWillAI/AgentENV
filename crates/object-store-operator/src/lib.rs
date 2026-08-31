mod auth;
mod operator;

pub use auth::{
    credential_source_from_fields, normalized_credential, parse_expiration,
    resolve_credential_from_process, CachedBearerTokenSource, CachedCredentialSource,
    CredentialFields, CredentialSource, CredentialSourceOptions, ResolvedBearerToken,
    ResolvedCredential, CREDENTIAL_PROCESS_TIMEOUT, CREDENTIAL_REFRESH_BUFFER,
    GOOGLE_METADATA_TOKEN_ENDPOINT,
};
pub use operator::{
    build_object_store_operator, run_with_refresh, AddressingStyle, ObjectStoreOperatorConfig,
    ObjectStoreOperatorError, ObjectStoreOperatorResult, OperatorWithCredential,
    DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT,
};

pub use opendal::{Error as OpenDalError, ErrorKind as OpenDalErrorKind, Operator};
pub type OpenDalResult<T> = opendal::Result<T>;
