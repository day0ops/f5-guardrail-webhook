# F5 Guardrail Webhook

[![Release](https://github.com/day0ops/f5-guardrail-webhook/actions/workflows/release.yml/badge.svg)](https://github.com/day0ops/f5-guardrail-webhook/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Image](https://img.shields.io/badge/registry-GAR-4285F4?logo=googlecloud)](https://console.cloud.google.com/artifacts/docker/field-engineering-apac/australia-southeast1/kasunt)

HTTP adapter for [agentgateway](https://agentgateway.dev)'s `promptGuard` webhook: calls F5 AI Guardrails' Scan API and translates the verdict into agentgateway's webhook action format (pass, mask, reject).

## What it does

- `GET /healthz` - liveness/readiness check.
- `POST /request` - scans the prompt against F5's Scan API. A blocked/flagged/rejected outcome rejects (403); redacted content masks the prompt; a malformed body rejects (400); a failed scan call rejects (503).
- `POST /response` - scans the response. This path never rejects: a blocked outcome masks the content to empty, redacted content masks with the redacted text, and a failed scan call also masks rather than raising a raw 5xx.

> [!IMPORTANT]
> By default (`SCAN_MODE=gated`), F5 sees the full conversation before anything is redacted per-message - this catches attacks split across turns that scanning messages in isolation would miss. Redaction itself still happens per-message, so it never overwrites unrelated content. Set `SCAN_MODE=batch` to scan the whole conversation as one blob instead - cheaper (one call total), but only safe for single-turn prompts.

## Configuration

| Env var                | Default  | Description                                                                                                                                                                                                                                                                                   |
| ---------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `F5_AISEC_URL`         | required | Base URL of F5 AI Guardrails' hosted Scan API                                                                                                                                                                                                                                                 |
| `F5_AISEC_TOKEN`       | required | Bearer token for the Scan API                                                                                                                                                                                                                                                                 |
| `CAI_PROJECT`          | required | F5 project name to scan against                                                                                                                                                                                                                                                               |
| `PORT`                 | `8000`   | HTTP listen port                                                                                                                                                                                                                                                                              |
| `SCAN_TIMEOUT_SECONDS` | `15`     | Per-scan-call timeout, in seconds                                                                                                                                                                                                                                                             |
| `SCAN_MODE`            | `gated`  | `gated`: one scan of the whole conversation decides block/no-block, then each message is scanned and redacted individually (1 call for a single message, 1+N otherwise). `batch`: one scan of the whole conversation only - cheaper, single-turn-safe only. Any other value is a fatal error. |

## Wiring it into agentgateway

Point an `EnterpriseAgentgatewayPolicy`'s `promptGuard` webhook at this service:

```yaml
spec:
  backend:
    ai:
      promptGuard:
        request:
          - webhook:
              backendRef: { name: f5-guardrail-webhook, port: 8000 }
        response:
          - webhook:
              backendRef: { name: f5-guardrail-webhook, port: 8000 }
```

> [!NOTE]
> Both endpoints always answer HTTP 200. The decision lives in the JSON body, not the transport status: `{"action": {"body"?, "status_code"?, "reason"}}`.

## Development

```bash
go vet ./...
go test ./... -race
go build ./cmd/f5-guardrail-webhook
```

## Releases

Trigger a release with `gh workflow run release.yml -f bump_type=patch` (or `minor`/`major`), or via the GitHub Actions UI. The workflow computes the next semver tag from the latest existing tag, creates that tag and a GitHub Release, builds and pushes a multi-arch image (`linux/amd64`, `linux/arm64`) to `australia-southeast1-docker.pkg.dev/field-engineering-apac/kasunt/f5-guardrail-webhook` tagged with the version and `latest`, then appends the image location to the release notes. Requires repo secrets `WIF_PROVIDER` and `WIF_SERVICE_ACCOUNT`. CI must have passed for the commit being released.
