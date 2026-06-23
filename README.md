# Wisec Agent

The Wisec agent runs inside a CI/CD pipeline. It collects build metadata, signs
it with an Ed25519 key, and submits it to the [Wisec](https://wisec.io) API,
which notarizes the build and runs supply-chain analysis (CVEs, secrets, SBOM
diff, typosquatting).

It is designed to be auditable: it is the only Wisec component that runs inside
your infrastructure, so its source is public. **Your source code is never read,
transmitted or stored** — the agent only collects dependency manifests and
commit metadata.

## What it sends

For each build the agent produces a signed, canonical payload containing:

- commit hash, branch, author email, timestamp
- changed and deleted files (paths only)
- dependency coordinates parsed from manifests
- the gitleaks secret-scanning report
- a CycloneDX SBOM (generated if the build does not provide one)
- an optional SARIF report from another scanner
- a manifest committing to the SHA-256 of the build artifacts
- the hash of the previous build, to chain-link builds

The canonical form is hashed with SHA-256 and signed with Ed25519. The signature
and the canonical data travel with the event so the API can verify them.

## Modes

```sh
wisec-agent          # collect, sign and submit the build event (non-blocking)
wisec-agent --gate   # wait for policy evaluation, exit non-zero on a block
```

`wisec-agent` is fire-and-forget: it never fails the build. Policy enforcement
happens exclusively in the `--gate` step, run after build and tests, which polls
the API until analysis completes and exits non-zero when a policy blocks.

## Installation

```sh
go install github.com/wisec-io/wisec-agent@latest
```

Or build a static binary from source:

```sh
make build        # produces ./wisec-agent
```

## Configuration

The agent auto-detects the CI environment (GitLab CI, GitHub Actions, Jenkins,
Azure DevOps). It is configured through environment variables.

| Variable | Required | Description |
|---|---|---|
| `AGENT_PRIVATE_KEY_HEX` | in CI | Ed25519 private key, hex-encoded (64 bytes). A throwaway key is generated when unset (local testing only). |
| `WISEC_API_ENDPOINT` | yes | Events endpoint, e.g. `https://api.wisec.io/api/v1/events`. |
| `WISEC_PROJECT_ID` | yes | Numeric Wisec project ID. |
| `WISEC_APP_URL` | no | Dashboard base URL. Derived from the API endpoint when unset. |
| `WISEC_BINARY_PATH` | no | Path to a build artifact to hash into the manifest. |
| `WISEC_SBOM_PATH` | no | Path to an existing SBOM. Auto-detected, otherwise generated. |
| `WISEC_SCAN_REPORT_PATH` | no | Path to a SARIF report from another scanner. |
| `WISEC_BUILD_DURATION_SECONDS` | no | Build duration to report, if the pipeline measures it. |
| `WISEC_VERBOSE` | no | Set to `true` for verbose logging. |

Gate mode adds:

| Variable | Default | Description |
|---|---|---|
| `WISEC_GATE_TIMEOUT` | `120` | Seconds to wait for analysis. |
| `WISEC_STRICT` | `false` | Block the build if the gate times out. |

## Usage in CI

GitLab CI:

```yaml
wisec_notify:
  stage: notify
  script:
    - wisec-agent

wisec_gate:
  stage: gate
  script:
    - wisec-agent --gate
```

GitHub Actions:

```yaml
- name: Wisec notify
  run: wisec-agent
- name: Wisec gate
  run: wisec-agent --gate
```

Provide `AGENT_PRIVATE_KEY_HEX`, `WISEC_API_ENDPOINT` and `WISEC_PROJECT_ID` as
protected CI variables.

## Development

```sh
make test   # run the test suite
make fmt    # gofmt and vet
make build  # build the binary
```

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
