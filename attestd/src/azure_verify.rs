//! In-enclave Azure `OpenAI` owner-capture verification.
//!
//! This module intentionally uses a narrow `reqwest` + serde surface instead
//! of Azure SDK crates. The attested binary runs these checks before binding
//! its listener and then periodically after binding; unsafe verification
//! failures are fatal to keep the miner fail-closed.

use std::collections::{BTreeMap, BTreeSet};
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
const REQUIRE_ASYNC_FILTER_ENV: &str = "GM_AZURE_REQUIRE_ASYNC_FILTER";
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
    require_async_filter: bool,
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
    suffix: &'static str,
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

#[derive(Debug, Deserialize)]
struct ArmDeploymentList {
    #[serde(default)]
    value: Vec<ArmDeployment>,
    #[serde(rename = "nextLink")]
    next_link: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ArmDeployment {
    name: String,
    #[serde(default)]
    properties: ArmDeploymentProperties,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArmDeploymentProperties {
    rai_policy_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ArmRaiPolicy {
    #[serde(default)]
    properties: ArmRaiPolicyProperties,
}

#[derive(Debug, Default, Deserialize)]
struct ArmRaiPolicyProperties {
    mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamingConfigAssessment {
    deployment_count: usize,
    checked_policy_count: usize,
    violations: Vec<StreamingConfigViolation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StreamingConfigViolation {
    MissingRaiPolicy {
        deployment: String,
    },
    SynchronousMode {
        policy: String,
        mode: Option<String>,
        deployments: Vec<String>,
    },
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
            require_async_filter: env_bool_default(REQUIRE_ASYNC_FILTER_ENV, true)?,
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
    verify_async_filter_configuration(&client, config, &endpoint, &token).await?;
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

fn env_bool_default(name: &str, default: bool) -> Result<bool> {
    match std::env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => bail!("{name} must be a boolean: true/false, 1/0, yes/no, or on/off"),
        },
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
    let suffix = AZURE_OPENAI_ALLOWED_SUFFIXES
        .iter()
        .copied()
        .find(|suffix| host_allowed_by_suffix(&host, suffix));
    let Some(suffix) = suffix else {
        bail!(
            "AZURE_OPENAI_ENDPOINT host '{host}' is not in the allowed suffix set: {}",
            AZURE_OPENAI_ALLOWED_SUFFIXES
                .map(|suffix| &suffix[1..])
                .join(", ")
        );
    };
    let account_name = host
        .split('.')
        .next()
        .context("AZURE_OPENAI_ENDPOINT host must contain an account label")?
        .to_owned();
    Ok(AzureEndpoint {
        host,
        account_name,
        suffix,
    })
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

async fn fetch_arm_deployments(
    client: &Client,
    config: &AzureVerifyConfig,
    endpoint: &AzureEndpoint,
    token: &str,
) -> Result<ArmDeploymentList> {
    let mut url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.CognitiveServices/accounts/{}/deployments?api-version={ARM_API_VERSION}",
        encode_path_segment(&config.subscription_id),
        encode_path_segment(&config.resource_group),
        encode_path_segment(&endpoint.account_name),
    );
    let mut deployments = Vec::new();
    loop {
        let page: ArmDeploymentList =
            get_json(client, &url, token, "Azure OpenAI deployments").await?;
        deployments.extend(page.value);
        let Some(next_link) = page.next_link else {
            break;
        };
        if next_link.trim().is_empty() {
            bail!("Azure OpenAI deployments response had an empty nextLink");
        }
        url = next_link;
    }
    Ok(ArmDeploymentList {
        value: deployments,
        next_link: None,
    })
}

async fn fetch_arm_rai_policy(
    client: &Client,
    config: &AzureVerifyConfig,
    endpoint: &AzureEndpoint,
    policy_name: &str,
    token: &str,
) -> Result<ArmRaiPolicy> {
    let url = format!(
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.CognitiveServices/accounts/{}/raiPolicies/{}?api-version={ARM_API_VERSION}",
        encode_path_segment(&config.subscription_id),
        encode_path_segment(&config.resource_group),
        encode_path_segment(&endpoint.account_name),
        encode_path_segment(policy_name),
    );
    get_json(client, &url, token, "Azure OpenAI RAI policy").await
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
    let custom_subdomain = custom_subdomain.trim().to_ascii_lowercase();
    if custom_subdomain != endpoint.account_name {
        bail!(
            "Azure account properties.customSubDomainName '{custom_subdomain}' does not match configured endpoint account label '{}'",
            endpoint.account_name
        );
    }
    let expected_host = format!("{custom_subdomain}{}", endpoint.suffix);
    let arm_endpoint = account
        .properties
        .endpoint
        .as_deref()
        .context("Azure account properties.endpoint is missing")?;
    let arm_url = Url::parse(arm_endpoint)
        .with_context(|| format!("parse Azure account endpoint {arm_endpoint:?}"))?;
    if arm_url.scheme() != "https" {
        bail!("Azure account properties.endpoint must use https");
    }
    if !arm_url.username().is_empty() || arm_url.password().is_some() {
        bail!("Azure account properties.endpoint must not contain userinfo");
    }
    let arm_host = arm_url
        .host_str()
        .context("Azure account properties.endpoint must include a DNS host")?
        .to_ascii_lowercase();
    if arm_host != expected_host {
        bail!(
            "Azure account properties.endpoint host '{arm_host}' did not match expected '{expected_host}'",
        );
    }
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

async fn verify_async_filter_configuration(
    client: &Client,
    config: &AzureVerifyConfig,
    endpoint: &AzureEndpoint,
    token: &str,
) -> Result<()> {
    let deployments = fetch_arm_deployments(client, config, endpoint, token).await?;
    tracing::info!(
        deployment_count = deployments.value.len(),
        "checking Azure OpenAI deployment streaming configuration",
    );

    let mut referenced_policy_names = BTreeSet::new();
    for deployment in &deployments.value {
        let rai_policy_name = deployment
            .properties
            .rai_policy_name
            .as_deref()
            .filter(|name| !name.trim().is_empty());
        tracing::debug!(
            deployment = %deployment.name,
            rai_policy_name = rai_policy_name.unwrap_or("<missing>"),
            "Azure OpenAI deployment RAI policy mapping",
        );
        if let Some(rai_policy_name) = rai_policy_name {
            referenced_policy_names.insert(rai_policy_name.to_owned());
        }
    }

    let mut policy_modes = BTreeMap::new();
    for policy_name in referenced_policy_names {
        let policy = fetch_arm_rai_policy(client, config, endpoint, &policy_name, token).await?;
        tracing::debug!(
            rai_policy_name = %policy_name,
            mode = policy.properties.mode.as_deref().unwrap_or("<missing>"),
            "Azure OpenAI RAI policy mode resolved",
        );
        policy_modes.insert(policy_name, policy.properties.mode);
    }

    let assessment = assess_streaming_configuration(&deployments, &policy_modes);
    log_streaming_assessment(&assessment, config.require_async_filter)
}

fn assess_streaming_configuration(
    deployments: &ArmDeploymentList,
    policy_modes: &BTreeMap<String, Option<String>>,
) -> StreamingConfigAssessment {
    let mut deployments_by_policy = BTreeMap::<String, Vec<String>>::new();
    let mut violations = Vec::new();

    for deployment in &deployments.value {
        let deployment_name = if deployment.name.trim().is_empty() {
            "<unnamed>".to_owned()
        } else {
            deployment.name.clone()
        };
        match deployment
            .properties
            .rai_policy_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            Some(policy_name) => {
                deployments_by_policy
                    .entry(policy_name.to_owned())
                    .or_default()
                    .push(deployment_name);
            }
            None => {
                violations.push(StreamingConfigViolation::MissingRaiPolicy {
                    deployment: deployment_name,
                });
            }
        }
    }

    for (policy, deployments) in deployments_by_policy {
        let mode = policy_modes.get(&policy).cloned().unwrap_or(None);
        if !rai_policy_mode_allows_streaming(mode.as_deref()) {
            violations.push(StreamingConfigViolation::SynchronousMode {
                policy,
                mode,
                deployments,
            });
        }
    }

    StreamingConfigAssessment {
        deployment_count: deployments.value.len(),
        checked_policy_count: policy_modes.len(),
        violations,
    }
}

fn rai_policy_mode_allows_streaming(mode: Option<&str>) -> bool {
    matches!(mode, Some("Asynchronous_filter" | "Deferred"))
}

fn log_streaming_assessment(
    assessment: &StreamingConfigAssessment,
    require_async_filter: bool,
) -> Result<()> {
    if assessment.deployment_count == 0 {
        tracing::info!("no Azure OpenAI deployments to check for streaming configuration");
        return Ok(());
    }

    if assessment.violations.is_empty() {
        tracing::info!(
            deployment_count = assessment.deployment_count,
            rai_policy_count = assessment.checked_policy_count,
            "streaming configuration verified: all referenced Azure OpenAI RAI policies use Asynchronous_filter or Deferred",
        );
        return Ok(());
    }

    let violation_messages = assessment
        .violations
        .iter()
        .map(StreamingConfigViolation::message)
        .collect::<Vec<_>>()
        .join("; ");
    if require_async_filter {
        tracing::error!(
            violations = %violation_messages,
            "Azure OpenAI streaming configuration failed",
        );
        bail!("Azure OpenAI streaming configuration failed: {violation_messages}");
    }
    tracing::warn!(
        violations = %violation_messages,
        "Azure OpenAI streaming configuration is not fully asynchronous; GM_AZURE_REQUIRE_ASYNC_FILTER=false so verification will continue",
    );
    Ok(())
}

impl StreamingConfigViolation {
    fn message(&self) -> String {
        match self {
            Self::MissingRaiPolicy { deployment } => {
                format!("deployment '{deployment}' has no properties.raiPolicyName")
            }
            Self::SynchronousMode {
                policy,
                mode,
                deployments,
            } => {
                let mode = mode.as_deref().unwrap_or("<missing>");
                format!(
                    "deployment(s) '{}' reference RAI policy '{policy}' with synchronous mode '{mode}'",
                    deployments.join(", ")
                )
            }
        }
    }
}

fn classify_verification_error(error: &anyhow::Error) -> VerificationFailureKind {
    for cause in error.chain() {
        if let Some(status_error) = cause.downcast_ref::<AzureHttpStatusError>() {
            return if status_is_transient(status_error.status) {
                VerificationFailureKind::Transient
            } else {
                VerificationFailureKind::Definitive
            };
        }
        if let Some(reqwest_error) = cause.downcast_ref::<reqwest::Error>() {
            if reqwest_error.is_timeout()
                || reqwest_error.is_connect()
                || reqwest_error.is_decode()
                || reqwest_error.status().is_some_and(status_is_transient)
            {
                return VerificationFailureKind::Transient;
            }
        }
    }
    VerificationFailureKind::Definitive
}

fn status_is_transient(status: StatusCode) -> bool {
    status.is_server_error()
        || matches!(
            status,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::REQUEST_TIMEOUT
        )
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

    fn deployments_from_json(json: &str) -> ArmDeploymentList {
        serde_json::from_str(json).expect("deployment fixture must parse")
    }

    fn rai_policy_from_json(json: &str) -> ArmRaiPolicy {
        serde_json::from_str(json).expect("RAI policy fixture must parse")
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
    fn account_binding_accepts_services_ai_suffix_matching_endpoint() {
        let endpoint = parse_azure_openai_endpoint("https://acct.services.ai.azure.com/")
            .expect("valid endpoint must parse");
        let account = account_from_json(
            r#"{
                "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct",
                "kind": "AIServices",
                "properties": {
                    "customSubDomainName": "acct",
                    "endpoint": "https://acct.services.ai.azure.com/",
                    "raiMonitorConfig": null,
                    "userOwnedStorage": []
                }
            }"#,
        );
        assert!(assert_account_binding(&endpoint, &account).is_ok());
    }

    #[test]
    fn account_binding_rejects_custom_subdomain_mismatch() {
        let endpoint = valid_endpoint();
        let account = account_from_json(
            r#"{
                "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct",
                "kind": "OpenAI",
                "properties": {
                    "customSubDomainName": "other",
                    "endpoint": "https://acct.openai.azure.com/"
                }
            }"#,
        );
        let err = assert_account_binding(&endpoint, &account)
            .expect_err("custom subdomain mismatch must fail")
            .to_string();
        assert!(err.contains("customSubDomainName"), "{err}");
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
    fn streaming_configuration_accepts_asynchronous_filter_mode() {
        let deployments = deployments_from_json(
            r#"{
                "value": [{
                    "name": "gpt-5",
                    "properties": {"raiPolicyName": "async-policy"}
                }]
            }"#,
        );
        let policy = rai_policy_from_json(
            r#"{
                "properties": {"mode": "Asynchronous_filter"}
            }"#,
        );
        let policy_modes = BTreeMap::from([("async-policy".to_owned(), policy.properties.mode)]);

        let assessment = assess_streaming_configuration(&deployments, &policy_modes);
        assert!(assessment.violations.is_empty(), "{assessment:?}");
    }

    #[test]
    fn streaming_configuration_accepts_legacy_deferred_mode() {
        let deployments = deployments_from_json(
            r#"{
                "value": [{
                    "name": "gpt-5",
                    "properties": {"raiPolicyName": "deferred-policy"}
                }]
            }"#,
        );
        let policy = rai_policy_from_json(
            r#"{
                "properties": {"mode": "Deferred"}
            }"#,
        );
        let policy_modes = BTreeMap::from([("deferred-policy".to_owned(), policy.properties.mode)]);

        let assessment = assess_streaming_configuration(&deployments, &policy_modes);
        assert!(assessment.violations.is_empty(), "{assessment:?}");
    }

    #[test]
    fn streaming_configuration_rejects_blocking_mode() {
        let deployments = deployments_from_json(
            r#"{
                "value": [{
                    "name": "gpt-5",
                    "properties": {"raiPolicyName": "blocking-policy"}
                }]
            }"#,
        );
        let policy = rai_policy_from_json(
            r#"{
                "properties": {"mode": "Blocking"}
            }"#,
        );
        let policy_modes = BTreeMap::from([("blocking-policy".to_owned(), policy.properties.mode)]);

        let assessment = assess_streaming_configuration(&deployments, &policy_modes);
        assert_eq!(
            assessment.violations,
            vec![StreamingConfigViolation::SynchronousMode {
                policy: "blocking-policy".to_owned(),
                mode: Some("Blocking".to_owned()),
                deployments: vec!["gpt-5".to_owned()],
            }]
        );
    }

    #[test]
    fn streaming_configuration_rejects_default_mode() {
        let deployments = deployments_from_json(
            r#"{
                "value": [{
                    "name": "gpt-5",
                    "properties": {"raiPolicyName": "default-policy"}
                }]
            }"#,
        );
        let policy = rai_policy_from_json(
            r#"{
                "properties": {"mode": "Default"}
            }"#,
        );
        let policy_modes = BTreeMap::from([("default-policy".to_owned(), policy.properties.mode)]);

        let assessment = assess_streaming_configuration(&deployments, &policy_modes);
        assert_eq!(
            assessment.violations,
            vec![StreamingConfigViolation::SynchronousMode {
                policy: "default-policy".to_owned(),
                mode: Some("Default".to_owned()),
                deployments: vec!["gpt-5".to_owned()],
            }]
        );
    }

    #[test]
    fn streaming_configuration_rejects_missing_mode() {
        let deployments = deployments_from_json(
            r#"{
                "value": [{
                    "name": "gpt-5",
                    "properties": {"raiPolicyName": "missing-mode-policy"}
                }]
            }"#,
        );
        let policy = rai_policy_from_json(
            r#"{
                "properties": {}
            }"#,
        );
        let policy_modes =
            BTreeMap::from([("missing-mode-policy".to_owned(), policy.properties.mode)]);

        let assessment = assess_streaming_configuration(&deployments, &policy_modes);
        assert_eq!(
            assessment.violations,
            vec![StreamingConfigViolation::SynchronousMode {
                policy: "missing-mode-policy".to_owned(),
                mode: None,
                deployments: vec!["gpt-5".to_owned()],
            }]
        );
    }

    #[test]
    fn streaming_configuration_accepts_empty_deployments_list() {
        let deployments = deployments_from_json(r#"{"value": []}"#);
        let policy_modes = BTreeMap::new();

        let assessment = assess_streaming_configuration(&deployments, &policy_modes);
        assert_eq!(assessment.deployment_count, 0);
        assert!(assessment.violations.is_empty(), "{assessment:?}");
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

        for status in [StatusCode::TOO_MANY_REQUESTS, StatusCode::REQUEST_TIMEOUT] {
            let transient_status = anyhow::Error::new(AzureHttpStatusError {
                label: "Azure Cognitive Services account",
                status,
                body: "throttled".to_owned(),
            });
            assert_eq!(
                classify_verification_error(&transient_status),
                VerificationFailureKind::Transient
            );
        }

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
