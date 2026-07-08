mod streaming;

use anyhow::{bail, Context, Result};
use reqwest::Url;
use serde_json::Value;

pub(crate) use self::streaming::{assess_streaming_configuration, log_streaming_assessment};
use super::arm::{ArmAccount, DiagnosticLog, DiagnosticSettingsList};
use super::endpoint::AzureEndpoint;

const ALLOWED_ACCOUNT_KINDS: [&str; 2] = ["OpenAI", "AIServices"];
const ALLOWED_DIAGNOSTIC_LOG_CATEGORIES: [&str; 4] = [
    "Audit",
    "RequestResponse",
    "Trace",
    "AzureOpenAIRequestUsage",
];
const ALLOWED_DIAGNOSTIC_LOG_CATEGORY_GROUPS: [&str; 2] = ["allLogs", "audit"];

pub(crate) fn assert_account_binding<'account>(
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

pub(crate) fn non_empty_json_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
        Value::String(value) => !value.trim().is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

pub(crate) fn warn_on_unexpected_diagnostic_logs(settings: &DiagnosticSettingsList) {
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

pub(crate) fn diagnostic_log_is_allowed(log: &DiagnosticLog) -> bool {
    log.category
        .as_deref()
        .is_some_and(|category| ALLOWED_DIAGNOSTIC_LOG_CATEGORIES.contains(&category))
        || log
            .category_group
            .as_deref()
            .is_some_and(|group| ALLOWED_DIAGNOSTIC_LOG_CATEGORY_GROUPS.contains(&group))
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "unit tests intentionally fail hard on malformed fixtures"
)]
mod tests {
    use super::*;
    use crate::azure_verify::arm::ArmAccount;
    use crate::azure_verify::endpoint::parse_azure_openai_endpoint;

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
}
