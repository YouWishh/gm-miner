# Azure OpenAI Owner-Capture Verification Notes

## Enforced at startup and continuously

When `OPENAI_UPSTREAM=azure`, `image/start.sh` first runs `gm-miner-attestd --verify-azure-once` as a blocking gate. Envoy is not rendered, RA-TLS is not provisioned, and no serving process is started until that one-shot verification exits successfully. A verification failure exits the container non-zero so the runtime restarts it.

The gate fails closed if:

- `AZURE_OPENAI_ENDPOINT` is not `https`, contains userinfo, or is outside the allowed Azure suffixes: `.openai.azure.com`, `.services.ai.azure.com`, `.cognitiveservices.azure.com`.
- ARM cannot read the bound `Microsoft.CognitiveServices/accounts/{name}` resource, where `{name}` is the leftmost endpoint host label.
- The ARM account `kind` is not `OpenAI` or `AIServices`.
- `properties.customSubDomainName` is missing or does not match the configured endpoint account label.
- `properties.endpoint` does not use the same host as the configured Azure endpoint, including the configured allowed suffix.
- `properties.raiMonitorConfig` is non-null.
- `properties.userOwnedStorage` is non-null and non-empty.
- Any deployment on the account references a Responsible AI policy whose `properties.mode` is not `Asynchronous_filter` or legacy `Deferred`. `Blocking`, `Default`, an absent mode, or a deployment with no `properties.raiPolicyName` is treated as synchronous buffering and fails closed by default.

The streaming check uses the same scoped Entra credentials and ARM API version as the account binding check:

- List deployments: `GET https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.CognitiveServices/accounts/{name}/deployments?api-version=2024-10-01`
- Read each distinct referenced RAI policy: `GET https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.CognitiveServices/accounts/{name}/raiPolicies/{raiPolicyName}?api-version=2024-10-01`

The verifier reads `value[].properties.raiPolicyName` from the deployment list, then reads `properties.mode` from each referenced RAI policy. Streaming is considered enabled only when the mode is `Asynchronous_filter` or `Deferred`. The verifier checks all deployments on the account so the attestation covers whatever the gateway may route to. If the account has zero deployments, the streaming check passes and logs that there are no deployments to check; model availability is gated elsewhere.

`GM_AZURE_REQUIRE_ASYNC_FILTER` controls the posture for synchronous policies. It defaults to `true`, which fails the one-shot startup gate and periodic verification on any synchronous/buffering deployment. Set it to `false` only as an explicit break-glass override; synchronous deployments are then logged as warnings but do not fail verification. ARM read failures still use the normal transient-vs-definitive handling.

Diagnostic settings are checked as defense in depth. Enabled native metadata categories are allowed: `Audit`, `RequestResponse`, `Trace`, `AzureOpenAIRequestUsage`; category groups `allLogs` and `audit` are allowed. Unknown enabled categories are logged as warnings, not fatal.

After the startup gate passes and the listener binds, `attestd` re-runs the same Azure owner-capture verification periodically, including the deployment streaming-mode check. The default interval is 900 seconds and can be overridden with `GM_AZURE_VERIFY_INTERVAL_SECS`; values below 60 seconds are clamped to 60 seconds. Transient verification errors such as Azure management/login network errors, timeouts, HTTP 408/429/5xx responses, or response decode failures are tolerated for 3 consecutive checks by default (`GM_AZURE_VERIFY_TRANSIENT_FAILURE_LIMIT`). A definitive verification failure, such as `raiMonitorConfig` becoming non-null, endpoint binding changing, account kind changing, async filtering being disabled, or other policy mismatch, stops `attestd` immediately with a non-zero exit so the container restarts and the boot-time gate blocks serving.

Envoy also pins Azure upstream TLS to the baked Azure root bundle and exact DNS SAN for the configured Azure host. Direct `api.openai.com` keeps the system CA bundle and existing behavior.

## Required miner configuration

Azure miners must provide:

- `OPENAI_UPSTREAM=azure`
- `AZURE_OPENAI_ENDPOINT`
- `AZURE_OPENAI_API_KEY`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`
- `AZURE_RESOURCE_GROUP`
- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET`

The Entra app/service principal should have `Reader` scoped to the Azure OpenAI resource so `attestd` can read the account and diagnostic settings without broader permissions.

Azure deployments must use a content-filter RAI policy configured for asynchronous filtering. In ARM, this is the RAI policy `mode`, not a deployment-level `contentFilters` field. The deployment's `properties.raiPolicyName` must point to a policy whose `properties.mode` is `Asynchronous_filter` or `Deferred`; the default synchronous modes buffer completions under `stream:true` and are not allowed for gm Azure miners.

## Baked CA bundle

Added `image/azure-roots.pem`, copied into the image at `/etc/gm/azure-roots.pem`.

The bundle contains:

- DigiCert Global Root G2, thumbprint `DF3C24F9BFD666761B268073FE06D1CC8D4F82A4`.
- Microsoft RSA Root Certificate Authority 2017.

DigiCert Global Root G1 is intentionally excluded because it is distrusted 2026-04-15. TODO: verify the exact PEM bytes at build time.

## Residual gaps

- Private Link or owner-controlled networking can observe only ciphertext under this model; it is not plaintext prompt capture unless TLS is broken or terminated outside Envoy.
- Unknown future Azure persistence/logging features may need additions to the ARM fail-closed checks or diagnostic allowlist.
- TODO: add the client-certificate assertion OAuth variant.
- TODO: confirm CVM egress to `login.microsoftonline.com` and `management.azure.com` in the target deployment environment.
