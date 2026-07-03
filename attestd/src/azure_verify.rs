//! In-enclave Azure `OpenAI` owner-capture verification.
//!
//! This module intentionally uses a narrow `reqwest` + serde surface instead
//! of Azure SDK crates. The attested binary runs these checks before binding
//! its listener and then periodically after binding; unsafe verification
//! failures are fatal to keep the miner fail-closed.

use std::env::VarError;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use tokio::sync::oneshot;

const MANAGEMENT_SCOPE: &str = "https://management.azure.com/.default";
const ARM_API_VERSION: &str = "2024-10-01";
const DIAGNOSTIC_SETTINGS_API_VERSION: &str = "2021-05-01-preview";
const DEFAULT_VERIFY_INTERVAL_SECS: u64 = 15 * 60;
const MIN_VERIFY_INTERVAL_SECS: u64 = 60;
const DEFAULT_TRANSIENT_FAILURE_LIMIT: u32 = 3;
const MIN_TRANSIENT_FAILURE_LIMIT: u32 = 1;
const VERIFY_INTERVAL_ENV: &str = "GM_AZURE_VERIFY_INTERVAL_SECS";
const TRANSIENT_FAILURE_LIMIT_ENV: &str = "GM_AZURE_VERIFY_TRANSIENT_FAILURE_LIMIT";
const AZURE_OPENAI_ALLOWED_SUFFIXES: [&str; 3] = [
    ".openai.azure.com",
    ".services.ai.azure.com",
    ".cognitiveservices.azure.com",
];
const ALLOWED_ACCOUNT_KINDS: [&str; 2] = ["OpenAI", "AIServices"];
const ALLOWED_DIAGNOSTIC_LOG_CATEGORIES: [&str; 4] = [
    "Audit",
    "RequestResponse",
    "Trace",
    "AzureOpenAIRequestUsage",
];
const ALLOWED_DIAGNOSTIC_LOG_CATEGORY_GROUPS: [&str; 2] = ["allLogs", "audit"];

#[derive(Debug, Clone)]
struct AzureVerifyConfig {
    endpoint: String,
    tenant_id: String,
    subscription_id: String,
    resource_group: String,
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Clone, Copy)]
struct PeriodicAzureVerifySettings {
    interval: Duration,
    transient_failure_limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AzureEndpoint {
    host: String,
    account_name: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct ArmAccount {
    id: String,
    kind: String,
    #[serde(default)]
    properties: ArmAccountProperties,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArmAccountProperties {
    custom_sub_domain_name: Option<String>,
    endpoint: Option<String>,
    rai_monitor_config: Option<Value>,
    user_owned_storage: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct DiagnosticSettingsList {
    #[serde(default)]
    value: Vec<DiagnosticSetting>,
}

#[derive(Debug, Deserialize)]
struct DiagnosticSetting {
    #[serde(default)]
    properties: DiagnosticProperties,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticProperties {
    #[serde(default)]
    logs: Vec<DiagnosticLog>,
    workspace_id: Option<String>,
    storage_account_id: Option<String>,
    event_hub_authorization_rule_id: Option<String>,
    marketplace_partner_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticLog {
    category: Option<String>,
    category_group: Option<String>,
    #[serde(default)]
    enabled: bool,
}

#[derive(Debug, Error)]
#[error("{label} request failed ({status}): {body}")]
struct AzureHttpStatusError {
    label: &'static str,
    status: StatusCode,
    body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationFailureKind {
    Transient,
    Definitive,
}

impl AzureVerifyConfig {
    fn from_env() -> Result<Self> {
        Ok(Self {
            endpoint: required_env("AZURE_OPENAI_ENDPOINT")?,
            tenant_id: required_env("AZURE_TENANT_ID")?,
            subscription_id: required_env("AZURE_SUBSCRIPTION_ID")?,
            resource_group: required_env("AZURE_RESOURCE_GROUP")?,
            client_id: required_env("AZURE_CLIENT_ID")?,
            client_secret: required_env("AZURE_CLIENT_SECRET")?,
        })
    }
}

impl PeriodicAzureVerifySettings {
    fn from_env() -> Result<Self> {
        let interval_secs = env_u64_at_least(
            VERIFY_INTERVAL_ENV,
            DEFAULT_VERIFY_INTERVAL_SECS,
            MIN_VERIFY_INTERVAL_SECS,
        )?;
        let transient_failure_limit = env_u32_at_least(
            TRANSIENT_FAILURE_LIMIT_ENV,
            DEFAULT_TRANSIENT_FAILURE_LIMIT,
            MIN_TRANSIENT_FAILURE_LIMIT,
        )?;
        Ok(Self {
            interval: Duration::from_secs(interval_secs),
            transient_failure_limit,
        })
    }
}

impl DiagnosticProperties {
    fn destination_count(&self) -> usize {
        [
            self.workspace_id.as_ref(),
            self.storage_account_id.as_ref(),
            self.event_hub_authorization_rule_id.as_ref(),
            self.marketplace_partner_id.as_ref(),
        ]
        .into_iter()
        .flatten()
        .count()
    }
}

/// Verify the Azure `OpenAI` upstream configuration from process env.
///
/// # Errors
/// Returns an error when any required env var is missing, the endpoint is not
/// an allowed Azure `OpenAI` host, ARM cannot be queried, or the ARM resource
/// is not bound to the configured TLS destination with content-to-storage
/// persistence disabled.
pub async fn verify_azure_openai_config_from_env() -> Result<()> {
    let config = AzureVerifyConfig::from_env()?;
    verify_azure_openai_config(&config).await
}

/// Start periodic Azure `OpenAI` owner-capture verification from process env.
///
/// On definitive verification failure, or too many consecutive transient
/// failures, the task sends a shutdown reason through `fatal_shutdown`.
///
/// # Errors
/// Returns an error if verifier env is invalid or periodic settings cannot be
/// parsed.
pub fn spawn_periodic_azure_openai_verification_from_env(
    fatal_shutdown: oneshot::Sender<String>,
) -> Result<tokio::task::JoinHandle<()>> {
    let config = AzureVerifyConfig::from_env()?;
    let settings = PeriodicAzureVerifySettings::from_env()?;
    tracing::info!(
        interval_secs = settings.interval.as_secs(),
        transient_failure_limit = settings.transient_failure_limit,
        "starting periodic Azure OpenAI owner-capture verification",
    );
    Ok(tokio::spawn(run_periodic_azure_openai_verification(
        config,
        settings,
        fatal_shutdown,
    )))
}

async fn verify_azure_openai_config(config: &AzureVerifyConfig) -> Result<()> {
    let endpoint = parse_azure_openai_endpoint(&config.endpoint)?;
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build Azure verification HTTP client")?;

    // TODO: add the client-certificate assertion auth variant for deployments
    // that do not want a client secret in the encrypted CVM env.
    let token = fetch_entra_token(&client, config).await?;
    let account = fetch_arm_account(&client, config, &endpoint, &token).await?;
    let resource_id = assert_account_binding(&endpoint, &account)?;
    let diagnostics = fetch_diagnostic_settings(&client, resource_id, &token).await?;
    warn_on_unexpected_diagnostic_logs(&diagnostics);
    tracing::info!(
        azure_host = %endpoint.host,
        resource_id = %resource_id,
        "Azure OpenAI owner-capture verification passed",
    );
    Ok(())
}

async fn run_periodic_azure_openai_verification(
    config: AzureVerifyConfig,
    settings: PeriodicAzureVerifySettings,
    fatal_shutdown: oneshot::Sender<String>,
) {
    let mut transient_failures = 0_u32;
    loop {
        tokio::time::sleep(settings.interval).await;
        match verify_azure_openai_config(&config).await {
            Ok(()) => {
                if transient_failures > 0 {
                    tracing::info!(
                        recovered_after = transient_failures,
                        "periodic Azure OpenAI owner-capture verification recovered",
                    );
                    transient_failures = 0;
                }
            }
            Err(err) => match classify_verification_error(&err) {
                VerificationFailureKind::Definitive => {
                    let reason = format!(
                        "definitive Azure OpenAI owner-capture verification failure: {err:#}"
                    );
                    tracing::error!(error = %err, "periodic Azure OpenAI owner-capture verification failed definitively");
                    let _ = fatal_shutdown.send(reason);
                    return;
                }
                VerificationFailureKind::Transient => {
                    transient_failures = transient_failures.saturating_add(1);
                    if transient_failures >= settings.transient_failure_limit {
                        let reason = format!(
                            "Azure OpenAI owner-capture verification had {transient_failures} consecutive transient failures (limit {}): {err:#}",
                            settings.transient_failure_limit
                        );
                        tracing::error!(
                            error = %err,
                            transient_failures,
                            transient_failure_limit = settings.transient_failure_limit,
                            "periodic Azure OpenAI owner-capture verification exceeded transient failure tolerance",
                        );
                        let _ = fatal_shutdown.send(reason);
                        return;
                    }
                    tracing::warn!(
                        error = %err,
                        transient_failures,
                        transient_failure_limit = settings.transient_failure_limit,
                        "periodic Azure OpenAI owner-capture verification hit a transient error",
                    );
                }
            },
        }
    }
}

fn required_env(name: &str) -> Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} must be set"))?;
    if value.trim().is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(value)
}

fn env_u64_at_least(name: &str, default: u64, minimum: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => {
            let parsed = value
                .parse::<u64>()
                .with_context(|| format!("{name} must be an integer number of seconds"))?;
            if parsed < minimum {
                tracing::warn!(
                    name,
                    configured = parsed,
                    minimum,
                    "Azure verification interval below minimum; using minimum",
                );
                Ok(minimum)
            } else {
                Ok(parsed)
            }
        }
        Err(VarError::NotPresent) => Ok(default),
        Err(err) => Err(err).with_context(|| format!("read {name}")),
    }
}

fn env_u32_at_least(name: &str, default: u32, minimum: u32) -> Result<u32> {
    match std::env::var(name) {
        Ok(value) => {
            let parsed = value
                .parse::<u32>()
                .with_context(|| format!("{name} must be a positive integer"))?;
            if parsed < minimum {
                tracing::warn!(
                    name,
                    configured = parsed,
                    minimum,
                    "Azure verification transient failure limit below minimum; using minimum",
                );
                Ok(minimum)
            } else {
                Ok(parsed)
            }
        }
        Err(VarError::NotPresent) => Ok(default),
        Err(err) => Err(err).with_context(|| format!("read {name}")),
    }
}

fn parse_azure_openai_endpoint(endpoint: &str) -> Result<AzureEndpoint> {
    let url = Url::parse(endpoint)
        .with_context(|| format!("parse AZURE_OPENAI_ENDPOINT {endpoint:?}"))?;
    if url.scheme() != "https" {
        bail!("AZURE_OPENAI_ENDPOINT must use https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("AZURE_OPENAI_ENDPOINT must not contain userinfo");
    }
    let host = url
        .host_str()
        .context("AZURE_OPENAI_ENDPOINT must include a DNS host")?
        .to_ascii_lowercase();
    validate_dns_host("AZURE_OPENAI_ENDPOINT host", &host)?;
    if !AZURE_OPENAI_ALLOWED_SUFFIXES
        .iter()
        .any(|suffix| host_allowed_by_suffix(&host, suffix))
    {
        bail!(
            "AZURE_OPENAI_ENDPOINT host '{host}' is not in the allowed suffix set: {}",
            AZURE_OPENAI_ALLOWED_SUFFIXES
                .map(|suffix| &suffix[1..])
                .join(", ")
        );
    }
    let account_name = host
        .split('.')
        .next()
        .context("AZURE_OPENAI_ENDPOINT host must contain an account label")?
        .to_owned();
    Ok(AzureEndpoint { host, account_name })
}

fn validate_dns_host(label: &str, host: &str) -> Result<()> {
    let valid = !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if valid {
        Ok(())
    } else {
        bail!("{label} must be a DNS host (got '{host}')")
    }
}

fn host_allowed_by_suffix(host: &str, suffix: &str) -> bool {
    host.len() > suffix.len() && host.ends_with(suffix)
}

async fn fetch_entra_token(client: &Client, config: &AzureVerifyConfig) -> Result<String> {
    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        encode_path_segment(&config.tenant_id)
    );
    let response = client
        .post(&url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("scope", MANAGEMENT_SCOPE),
        ])
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(AzureHttpStatusError {
            label: "Entra token",
            status,
            body,
        }
        .into());
    }
    let token: TokenResponse = response
        .json()
        .await
        .context("parse Entra token response")?;
    if token.access_token.trim().is_empty() {
        bail!("Entra token response had an empty access_token");
    }
    Ok(token.access_token)
}

async fn fetch_arm_account(
    client: &Client,
    config: &AzureVerifyConfig,
    endpoint: &AzureEndpoint,
    token: &str,
) -> Result<ArmAccount> {
    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.CognitiveServices/accounts/{}?api-version={ARM_API_VERSION}",
        encode_path_segment(&config.subscription_id),
        encode_path_segment(&config.resource_group),
        encode_path_segment(&endpoint.account_name),
    );
    get_json(client, &url, token, "Azure Cognitive Services account").await
}

async fn fetch_diagnostic_settings(
    client: &Client,
    resource_id: &str,
    token: &str,
) -> Result<DiagnosticSettingsList> {
    let resource_path = resource_id
        .strip_prefix('/')
        .with_context(|| format!("ARM resource id must start with '/': {resource_id}"))?;
    let url = format!(
        "https://management.azure.com/{resource_path}/providers/Microsoft.Insights/diagnosticSettings?api-version={DIAGNOSTIC_SETTINGS_API_VERSION}",
    );
    get_json(client, &url, token, "Azure diagnostic settings").await
}

async fn get_json<T: for<'de> Deserialize<'de>>(
    client: &Client,
    url: &str,
    token: &str,
    label: &'static str,
) -> Result<T> {
    let response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(AzureHttpStatusError {
            label,
            status,
            body,
        }
        .into());
    }
    response
        .json()
        .await
        .with_context(|| format!("parse {label} response"))
}

fn assert_account_binding<'account>(
    endpoint: &AzureEndpoint,
    account: &'account ArmAccount,
) -> Result<&'account str> {
    if !ALLOWED_ACCOUNT_KINDS.contains(&account.kind.as_str()) {
        bail!(
            "Azure account kind '{}' is not allowed; expected one of {}",
            account.kind,
            ALLOWED_ACCOUNT_KINDS.join(", ")
        );
    }
    let custom_subdomain = account
        .properties
        .custom_sub_domain_name
        .as_deref()
        .context("Azure account properties.customSubDomainName is missing")?;
    if custom_subdomain.trim().is_empty() {
        bail!("Azure account properties.customSubDomainName is empty");
    }
    let expected_endpoint = format!("https://{custom_subdomain}.openai.azure.com/");
    let arm_endpoint = account
        .properties
        .endpoint
        .as_deref()
        .context("Azure account properties.endpoint is missing")?;
    if arm_endpoint != expected_endpoint {
        bail!(
            "Azure account properties.endpoint '{arm_endpoint}' did not match expected '{expected_endpoint}'",
        );
    }
    let arm_host = Url::parse(arm_endpoint)
        .with_context(|| format!("parse Azure account endpoint {arm_endpoint:?}"))?
        .host_str()
        .context("Azure account properties.endpoint must include a DNS host")?
        .to_ascii_lowercase();
    if arm_host != endpoint.host {
        bail!(
            "Azure account endpoint host '{arm_host}' does not match configured AZURE_OPENAI_ENDPOINT host '{}'",
            endpoint.host
        );
    }
    if account
        .properties
        .rai_monitor_config
        .as_ref()
        .is_some_and(|value| !value.is_null())
    {
        bail!("Azure account properties.raiMonitorConfig must be null or absent");
    }
    if account
        .properties
        .user_owned_storage
        .as_ref()
        .is_some_and(non_empty_json_value)
    {
        bail!("Azure account properties.userOwnedStorage must be null, absent, or empty");
    }
    if account.id.trim().is_empty() {
        bail!("Azure account id is empty");
    }
    Ok(&account.id)
}

fn non_empty_json_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
        Value::String(value) => !value.trim().is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn warn_on_unexpected_diagnostic_logs(settings: &DiagnosticSettingsList) {
    for setting in &settings.value {
        let destination_count = setting.properties.destination_count();
        for log in &setting.properties.logs {
            if log.enabled && !diagnostic_log_is_allowed(log) {
                tracing::warn!(
                    category = log.category.as_deref().unwrap_or("<none>"),
                    category_group = log.category_group.as_deref().unwrap_or("<none>"),
                    destinations = destination_count,
                    "Azure diagnostic setting has an enabled unknown log category; not fatal because native categories are metadata-only",
                );
            }
        }
    }
}

fn diagnostic_log_is_allowed(log: &DiagnosticLog) -> bool {
    log.category
        .as_deref()
        .is_some_and(|category| ALLOWED_DIAGNOSTIC_LOG_CATEGORIES.contains(&category))
        || log
            .category_group
            .as_deref()
            .is_some_and(|group| ALLOWED_DIAGNOSTIC_LOG_CATEGORY_GROUPS.contains(&group))
}

fn classify_verification_error(error: &anyhow::Error) -> VerificationFailureKind {
    for cause in error.chain() {
        if let Some(status_error) = cause.downcast_ref::<AzureHttpStatusError>() {
            return if status_error.status.is_server_error() {
                VerificationFailureKind::Transient
            } else {
                VerificationFailureKind::Definitive
            };
        }
        if let Some(reqwest_error) = cause.downcast_ref::<reqwest::Error>() {
            if reqwest_error.is_timeout()
                || reqwest_error.is_connect()
                || reqwest_error.is_decode()
                || reqwest_error
                    .status()
                    .is_some_and(|status| status.is_server_error())
            {
                return VerificationFailureKind::Transient;
            }
        }
    }
    VerificationFailureKind::Definitive
}

fn encode_path_segment(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                encoded.push('%');
                encoded.push(char::from(HEX[usize::from(byte >> 4)]));
                encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
    encoded
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "unit tests intentionally fail hard on malformed fixtures"
)]
mod tests {
    use super::*;

    fn valid_endpoint() -> AzureEndpoint {
        parse_azure_openai_endpoint("https://acct.openai.azure.com/")
            .expect("valid endpoint must parse")
    }

    fn account_from_json(json: &str) -> ArmAccount {
        serde_json::from_str(json).expect("fixture must parse")
    }

    fn valid_account_json() -> &'static str {
        r#"{
            "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct",
            "kind": "OpenAI",
            "properties": {
                "customSubDomainName": "acct",
                "endpoint": "https://acct.openai.azure.com/",
                "raiMonitorConfig": null,
                "userOwnedStorage": []
            }
        }"#
    }

    #[test]
    fn base_url_allowlist_accepts_azure_openai_suffixes() {
        for endpoint in [
            "https://acct.openai.azure.com/",
            "https://acct.services.ai.azure.com",
            "https://acct.cognitiveservices.azure.com/openai",
        ] {
            assert!(
                parse_azure_openai_endpoint(endpoint).is_ok(),
                "{endpoint} should be accepted"
            );
        }
    }

    #[test]
    fn base_url_allowlist_rejects_non_https_userinfo_and_bad_suffix() {
        for endpoint in [
            "http://acct.openai.azure.com",
            "acct.openai.azure.com",
            "https://user@acct.openai.azure.com",
            "https://acct.openai.azure.com.evil.example",
            "https://api.evil.example",
        ] {
            assert!(
                parse_azure_openai_endpoint(endpoint).is_err(),
                "{endpoint} should be rejected"
            );
        }
    }

    #[test]
    fn account_binding_accepts_allowed_kind_matching_endpoint_and_no_storage() {
        let endpoint = valid_endpoint();
        let account = account_from_json(valid_account_json());
        assert!(assert_account_binding(&endpoint, &account).is_ok());
    }

    #[test]
    fn account_binding_rejects_endpoint_host_mismatch() {
        let endpoint = parse_azure_openai_endpoint("https://other.openai.azure.com/")
            .expect("valid endpoint must parse");
        let account = account_from_json(valid_account_json());
        let err = assert_account_binding(&endpoint, &account)
            .expect_err("host mismatch must fail")
            .to_string();
        assert!(err.contains("does not match configured"), "{err}");
    }

    #[test]
    fn account_binding_rejects_content_storage_paths() {
        for properties in [
            r#""raiMonitorConfig": {"enabled": true}, "userOwnedStorage": []"#,
            r#""raiMonitorConfig": null, "userOwnedStorage": [{"id": "storage"}]"#,
            r#""raiMonitorConfig": null, "userOwnedStorage": {"id": "storage"}"#,
        ] {
            let json = format!(
                r#"{{
                    "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct",
                    "kind": "OpenAI",
                    "properties": {{
                        "customSubDomainName": "acct",
                        "endpoint": "https://acct.openai.azure.com/",
                        {properties}
                    }}
                }}"#
            );
            let endpoint = valid_endpoint();
            let account = account_from_json(&json);
            assert!(
                assert_account_binding(&endpoint, &account).is_err(),
                "{properties} must fail"
            );
        }
    }

    #[test]
    fn account_binding_rejects_unallowed_kind() {
        let account = account_from_json(
            r#"{
                "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct",
                "kind": "CognitiveServices",
                "properties": {
                    "customSubDomainName": "acct",
                    "endpoint": "https://acct.openai.azure.com/"
                }
            }"#,
        );
        let err = assert_account_binding(&valid_endpoint(), &account)
            .expect_err("kind must fail")
            .to_string();
        assert!(
            err.contains("kind 'CognitiveServices' is not allowed"),
            "{err}"
        );
    }

    #[test]
    fn diagnostic_category_allowlist_accepts_known_metadata_logs() {
        for log in [
            DiagnosticLog {
                category: Some("Audit".to_owned()),
                category_group: None,
                enabled: true,
            },
            DiagnosticLog {
                category: Some("RequestResponse".to_owned()),
                category_group: None,
                enabled: true,
            },
            DiagnosticLog {
                category: None,
                category_group: Some("allLogs".to_owned()),
                enabled: true,
            },
            DiagnosticLog {
                category: None,
                category_group: Some("audit".to_owned()),
                enabled: true,
            },
        ] {
            assert!(diagnostic_log_is_allowed(&log));
        }
    }

    #[test]
    fn diagnostic_category_allowlist_flags_unknown_enabled_logs() {
        let log = DiagnosticLog {
            category: Some("FutureContentLog".to_owned()),
            category_group: None,
            enabled: true,
        };
        assert!(!diagnostic_log_is_allowed(&log));
    }

    #[test]
    fn verification_error_classification_separates_transient_from_definitive() {
        let transient = anyhow::Error::new(AzureHttpStatusError {
            label: "Azure Cognitive Services account",
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: "temporary outage".to_owned(),
        });
        assert_eq!(
            classify_verification_error(&transient),
            VerificationFailureKind::Transient
        );

        let definitive_status = anyhow::Error::new(AzureHttpStatusError {
            label: "Azure Cognitive Services account",
            status: StatusCode::FORBIDDEN,
            body: "access denied".to_owned(),
        });
        assert_eq!(
            classify_verification_error(&definitive_status),
            VerificationFailureKind::Definitive
        );

        let definitive_policy =
            anyhow::anyhow!("Azure account properties.raiMonitorConfig must be null or absent");
        assert_eq!(
            classify_verification_error(&definitive_policy),
            VerificationFailureKind::Definitive
        );
    }
}
