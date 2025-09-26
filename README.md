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

### Basic Usage

Create a `PulpAccessRequest` to generate authentication secrets:

```yaml
apiVersion: pulp.konflux-ci.dev/v1alpha1
kind: PulpAccessRequest
metadata:
  name: my-pulp-access
  namespace: my-namespace
spec:
  # OAuth2 credentials (optional)
  client_id: "my-client-id"
  client_secret: "my-client-secret"
  
  # Domain management (optional)
  domain: "my-pulp-domain"
  
  # Custom TLS certificate and key (optional)
  cert: |
    -----BEGIN CERTIFICATE-----
    ... your certificate content ...
    -----END CERTIFICATE-----
  key: |
    -----BEGIN PRIVATE KEY-----
    ... your private key content ...
    -----END PRIVATE KEY-----
```

### Pulp with Quay Backend

If you want Pulp to use Quay.io as storage backend:

```yaml
apiVersion: pulp.konflux-ci.dev/v1alpha1
kind: PulpAccessRequest
metadata:
  name: pulp-with-quay-backend
  namespace: my-namespace
spec:
  client_id: "my-oauth-client"
  client_secret: "my-oauth-secret"
  domain: "production-domain"
  use_quay_backend: true
  cert: |
    -----BEGIN CERTIFICATE-----
    ... certificate for mTLS ...
    -----END CERTIFICATE-----
  key: |
    -----BEGIN PRIVATE KEY-----
    ... private key for mTLS ...
    -----END PRIVATE KEY-----
```

## Generated Secret Structure

The controller creates a secret named `pulp-access` containing:

| Key | Description | When Included |
|-----|-------------|---------------|
| `cli.toml` | mTLS configuration for pulp-cli | Always |
| `oauth-cli.toml` | OAuth2 configuration for pulp-cli | When client credentials provided |
| `tls.crt` | TLS certificate | When custom certificate provided |
| `tls.key` | TLS private key | When custom key provided |
| `client_id` | OAuth2 client ID | When provided in spec |
| `client_secret` | OAuth2 client secret | When provided in spec |
| `domain` | Pulp domain name | When provided in spec |
