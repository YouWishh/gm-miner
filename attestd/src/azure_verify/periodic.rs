use tokio::sync::oneshot;

use super::config::{AzureVerifyConfig, PeriodicAzureVerifySettings};
use super::error::{classify_verification_error, VerificationFailureKind};
use super::verify_azure_openai_config;

pub(crate) async fn run_periodic_azure_openai_verification(
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
