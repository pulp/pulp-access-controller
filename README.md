# Pulp Access Controller

A Kubernetes operator that automates the creation of secrets for accessing Red Hat Pulp services. Built using the [Kopf framework](https://github.com/nolar/kopf), this controller watches for `PulpAccessRequest` custom resources and automatically provisions the necessary authentication materials.

## Overview

The Pulp Access Controller simplifies access management for Red Hat Pulp by automatically creating Kubernetes secrets containing:
- `cli.toml` - Configuration file for pulp-cli with mTLS settings (always included)
- `oauth-cli.toml` - Configuration file for pulp-cli with OAuth2 settings (when client credentials provided)
- `tls.crt` - Custom TLS certificate in base64 encoding (when custom certificate provided)
- `tls.key` - Custom TLS private key in base64 encoding (when custom key provided)
- `client_id` - OAuth2 client ID in base64 encoding (when provided)
- `client_secret` - OAuth2 client secret in base64 encoding (when provided)  
- `domain` - Pulp domain name in base64 encoding (when provided)
- Optional ImageRepository resources for Quay.io OCI backend integration

## Features

### **Multiple Authentication Methods**
- **mTLS Authentication**: Support for mutual TLS using custom certificates
- **OAuth2 Authentication**: Client credentials flow for API access
- **Flexible Configuration**: Mix and match authentication methods as needed

### **Automated Resource Management**
- **Domain Creation**: Automatically create Pulp domains via API
- **Quay Integration**: Optional OCI storage backend configuration with Quay.io
- **Secret Generation**: Automated Kubernetes secret creation with proper encoding

### **Easy Configuration**
- **Custom Certificates**: Bring your own TLS certificates and keys
- **CLI Ready**: Pre-configured `pulp-cli` configuration files included
- **Kubernetes Native**: Fully integrated with Kubernetes RBAC and lifecycle management

## Usage

### Step 1: Create a Credentials Secret

First, create a Kubernetes secret containing your credentials:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pulp-credentials
  namespace: my-namespace
type: Opaque
stringData:
  # OAuth2 credentials (optional, required for domain creation)
  client_id: "my-client-id"
  client_secret: "my-client-secret"
  
  # Custom TLS certificate and key (optional, for mTLS)
  # Option 1: Use 'cert' and 'key'
  cert: |
    -----BEGIN CERTIFICATE-----
    ... your certificate content ...
    -----END CERTIFICATE-----
  key: |
    -----BEGIN PRIVATE KEY-----
    ... your private key content ...
    -----END PRIVATE KEY-----
  
  # Option 2: Use 'tls.crt' and 'tls.key' (alternative naming)
  # tls.crt: |
  #   -----BEGIN CERTIFICATE-----
  #   ...
  #   -----END CERTIFICATE-----
  # tls.key: |
  #   -----BEGIN PRIVATE KEY-----
  #   ...
  #   -----END PRIVATE KEY-----
```

### Step 2: Create a PulpAccessRequest

Then, create a `PulpAccessRequest` that references your credentials secret:

```yaml
apiVersion: pulp.konflux-ci.dev/v1alpha1
kind: PulpAccessRequest
metadata:
  name: my-pulp-access
  namespace: my-namespace
spec:
  # Required: Name of the secret containing credentials
  credentialsSecretName: pulp-credentials
```

**Note**: The Pulp domain will be automatically created with the name `konflux-<namespace>`. For example, if your namespace is `my-namespace`, the domain will be `konflux-my-namespace`.

### Advanced: Pulp with Quay Backend

To configure Pulp with Quay.io as the OCI storage backend:

```yaml
apiVersion: pulp.konflux-ci.dev/v1alpha1
kind: PulpAccessRequest
metadata:
  name: pulp-with-quay-backend
  namespace: my-namespace
spec:
  credentialsSecretName: pulp-credentials
  use_quay_backend: true
```

The domain `konflux-my-namespace` will be automatically created and configured with Quay backend storage.

## Generated Secret Structure

The controller creates a secret named `pulp-access` containing:

| Key | Description | When Included |
|-----|-------------|---------------|
| `cli.toml` | mTLS configuration for pulp-cli | Always |
| `oauth-cli.toml` | OAuth2 configuration for pulp-cli | When client credentials in referenced secret |
| `tls.crt` | TLS certificate | When custom certificate in referenced secret |
| `tls.key` | TLS private key | When custom key in referenced secret |
| `client_id` | OAuth2 client ID | When provided in referenced secret |
| `client_secret` | OAuth2 client secret | When provided in referenced secret |
| `domain` | Pulp domain name (auto-generated as `konflux-<namespace>`) | Always |

## Credentials Secret Format

The credentials secret referenced by `credentialsSecretName` should contain:

| Key | Description | Required |
|-----|-------------|----------|
| `client_id` | OAuth2 client ID | Optional (required for domain creation) |
| `client_secret` | OAuth2 client secret | Optional (required for domain creation) |
| `cert` or `tls.crt` | TLS certificate in PEM format | Optional (for mTLS) |
| `key` or `tls.key` | TLS private key in PEM format | Optional (for mTLS) |

**Note**: The controller supports both `cert`/`key` and `tls.crt`/`tls.key` naming conventions for certificates.

## Checking Status

After creating a `PulpAccessRequest`, you can check its status to see if the processing completed successfully:

```bash
kubectl get pulpaccessrequest my-pulp-access -o yaml
```

### Status Fields

The controller updates the following status fields:

| Field | Type | Description |
|-------|------|-------------|
| `secretName` | string | Name of the generated secret (always `pulp-access`) |
| `domain` | string | The auto-generated Pulp domain name (`konflux-<namespace>`) |
| `domainCreated` | boolean | Whether the Pulp domain was successfully created |
| `imageRepositoryCreated` | boolean | Whether the ImageRepository was created (when `use_quay_backend: true`) |
| `quayBackendConfigured` | boolean | Whether Quay backend storage was configured (when `use_quay_backend: true`) |
| `conditions` | array | Array of condition objects with detailed status information |

### Status Conditions

The controller sets the following condition types:

| Condition Type | Status | Reason | Description |
|----------------|--------|--------|-------------|
| `Ready` | `True` | `SecretCreated` | The pulp-access secret was successfully created |
| `Ready` | `True` | `SecretExists` | The pulp-access secret already exists |
| `Ready` | `False` | `MissingCredentials` | The `credentialsSecretName` field is required but not provided |
| `Ready` | `False` | `SecretNotFound` | The referenced credentials secret was not found |
| `Ready` | `False` | `SecretReadError` | Error reading the credentials secret |
| `Ready` | `False` | `ApiError` | Kubernetes API error occurred |
| `Ready` | `False` | `UnexpectedError` | An unexpected error occurred |

### Example Status Output

```yaml
status:
  conditions:
  - lastTransitionTime: "2025-11-05T10:30:00Z"
    message: Successfully created secret 'pulp-access'
    reason: SecretCreated
    status: "True"
    type: Ready
  domain: konflux-my-namespace
  domainCreated: true
  imageRepositoryCreated: true
  quayBackendConfigured: true
  secretName: pulp-access
```

### Quick Status Check

To quickly check if your PulpAccessRequest is ready:

```bash
kubectl get pulpaccessrequest my-pulp-access -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'
```

This will output `True` if the request was processed successfully.

