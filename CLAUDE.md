# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Pulp Access Controller is a Kubernetes operator built with the [Kopf framework](https://github.com/nolar/kopf) that watches for `PulpAccessRequest` custom resources (API group `pulp.konflux-ci.dev/v1alpha1`) and automatically provisions secrets for accessing Red Hat Pulp services.

## Running the Operator

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally (requires kubeconfig with cluster access)
kopf run --standalone main.py

# Build container
docker build -f docker/Dockerfile -t pulp-access-controller .
```

There are no tests, linter configuration, or a Makefile in this project. CI/CD is handled by Tekton pipelines via Red Hat Konflux (see `.tekton/`).

## Architecture

The codebase has two source files:

- **`main.py`** — The entire operator. Contains Kopf event handlers (`@kopf.on.create`, `@kopf.on.update`, `@kopf.on.delete`) for `PulpAccessRequest` resources, plus all helper functions for Pulp API calls, secret management, and Quay backend configuration.
- **`pulp_oauth2_auth.py`** — Standalone OAuth2 client credentials auth library (`PulpOAuth2Session` extending `requests.Session`). Used for Red Hat SSO token-based authentication against the Pulp API. Not currently imported by `main.py` (main.py uses mTLS or Basic Auth directly).

### Key flow in main.py

1. **Create handler**: Validates credentials secret → extracts cert/key or username/password → creates Pulp domain via API → builds and creates `pulp-access` K8s secret → optionally creates ImageRepository CR and configures Quay OCI backend
2. **Update handler**: Re-reads credentials → updates or recreates the `pulp-access` secret
3. **Delete handler**: Cleans up `pulp-access` secret and ImageRepository if created

### Dual authentication

The operator supports certificate-based (mTLS) and Basic Auth. Certificate auth takes precedence when both are present. This affects:
- How credentials are extracted from the input secret (`extract_credentials_from_secret`)
- The generated `cli.toml` format (`generate_cli_toml`)
- How Pulp API calls are made (client certs via `temp_cert_files` context manager vs. HTTP Basic Auth)

### Key constants (main.py)

- `PULP_API_BASE_URL` = `https://mtls.internal.console.redhat.com`
- `PULP_ACCESS_SECRET_NAME` = `pulp-access` (the output secret name)
- Domain naming convention: `konflux-<namespace>`

## Kubernetes Resources

- **CRD**: `kubernetes/crd.yaml` — defines `PulpAccessRequest` with spec fields `credentialsSecretName` and `use_quay_backend`
- **RBAC/Deployment**: `kubernetes/` directory contains role, rolebinding, serviceaccount, and deployment manifests
- **Kustomize**: `config/manifests/{production,staging}/` bundle all manifests with namespace set to `pulp-access-controller`

## Dependencies

Only three Python packages: `kopf`, `kubernetes`, `requests`. No dev dependencies or test frameworks are configured.
