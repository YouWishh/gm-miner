# Azure OpenAI Owner-Capture Verification Notes

## Enforced at startup and continuously

When `OPENAI_UPSTREAM=azure`, `gm-miner-attestd` fails closed before binding if:

- `AZURE_OPENAI_ENDPOINT` is not `https`, contains userinfo, or is outside the allowed Azure suffixes: `.openai.azure.com`, `.services.ai.azure.com`, `.cognitiveservices.azure.com`.
- ARM cannot read the bound `Microsoft.CognitiveServices/accounts/{name}` resource, where `{name}` is the leftmost endpoint host label.
- The ARM account `kind` is not `OpenAI` or `AIServices`.
- `properties.customSubDomainName` is missing, or `properties.endpoint` is not exactly `https://{customSubDomainName}.openai.azure.com/`.
- The ARM endpoint host does not match the configured Azure endpoint host.
- `properties.raiMonitorConfig` is non-null.
- `properties.userOwnedStorage` is non-null and non-empty.

Diagnostic settings are checked as defense in depth. Enabled native metadata categories are allowed: `Audit`, `RequestResponse`, `Trace`, `AzureOpenAIRequestUsage`; category groups `allLogs` and `audit` are allowed. Unknown enabled categories are logged as warnings, not fatal.

After the startup check passes and the listener binds, `attestd` re-runs the same Azure owner-capture verification periodically. The default interval is 900 seconds and can be overridden with `GM_AZURE_VERIFY_INTERVAL_SECS`; values below 60 seconds are clamped to 60 seconds. Transient verification errors such as Azure management/login network errors, timeouts, 5xx responses, or response decode failures are tolerated for 3 consecutive checks by default (`GM_AZURE_VERIFY_TRANSIENT_FAILURE_LIMIT`). A definitive verification failure, such as `raiMonitorConfig` becoming non-null, endpoint binding changing, account kind changing, or other policy mismatch, stops `attestd` immediately with a non-zero exit so the container restarts and the boot-time gate blocks serving.

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
