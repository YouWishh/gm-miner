use anyhow::{bail, Context, Result};
use reqwest::Url;

pub(crate) const AZURE_OPENAI_ALLOWED_SUFFIXES: [&str; 3] = [
    ".openai.azure.com",
    ".services.ai.azure.com",
    ".cognitiveservices.azure.com",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AzureEndpoint {
    pub(crate) host: String,
    pub(crate) account_name: String,
    pub(crate) suffix: &'static str,
}

pub(crate) fn parse_azure_openai_endpoint(endpoint: &str) -> Result<AzureEndpoint> {
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

pub(crate) fn validate_dns_host(label: &str, host: &str) -> Result<()> {
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

pub(crate) fn host_allowed_by_suffix(host: &str, suffix: &str) -> bool {
    host.len() > suffix.len() && host.ends_with(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
