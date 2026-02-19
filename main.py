import kopf
import kubernetes.client
from kubernetes.client.rest import ApiException
import requests
import base64
import os
import time
import json
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any

# Configuration constants
PULP_API_BASE_URL = "https://packages.redhat.com"
PULP_ACCESS_SECRET_NAME = "pulp-access"
IMAGE_REPO_NAME = "pulp-access-controller-imagerepo"
IMAGE_REPO_SECRET_SUFFIX = "-image-push"


class StatusTracker:
    """Tracks the status of a PulpAccessRequest processing."""
    
    def __init__(self):
        self.data = {
            'secretName': PULP_ACCESS_SECRET_NAME,
            'domain': None,
            'domainCreated': False,
            'imageRepositoryCreated': False,
            'quayBackendConfigured': False,
            'conditions': []
        }
    
    def add_condition(self, condition_type: str, status_value: str, reason: str, message: str) -> dict:
        """Add a condition to the status."""
        condition = {
            'type': condition_type,
            'status': status_value,
            'reason': reason,
            'message': message,
            'lastTransitionTime': datetime.now(timezone.utc).isoformat()
        }
        self.data['conditions'].append(condition)
        return condition


@contextmanager
def temp_cert_files(cert: str, key: str):
    """Context manager for temporary certificate files."""
    cert_path = None
    key_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as cert_file:
            cert_file.write(cert)
            cert_path = cert_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as key_file:
            key_file.write(key)
            key_path = key_file.name
        
        yield cert_path, key_path
    finally:
        if cert_path and os.path.exists(cert_path):
            os.unlink(cert_path)
        if key_path and os.path.exists(key_path):
            os.unlink(key_path)


def create_owner_reference(body: dict) -> kubernetes.client.V1OwnerReference:
    """Create an owner reference for Kubernetes resources."""
    return kubernetes.client.V1OwnerReference(
        api_version=body['apiVersion'],
        kind=body['kind'],
        name=body['metadata']['name'],
        uid=body['metadata']['uid'],
        controller=True,
        block_owner_deletion=True,
    )


def extract_credentials_from_secret(secret_data: dict, logger) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Extract credentials from a Kubernetes secret.
    Supports both certificate-based (mTLS) and username/password (Basic Auth) authentication.
    
    Returns:
        Tuple of (cert, key, username, password)
        - If username/password are present, they take precedence (Basic Auth)
        - If only cert/key are present, use mTLS auth
    """
    custom_cert = None
    custom_key = None
    username = None
    password = None
    
    # Extract certificate credentials
    if 'cert' in secret_data or 'tls.crt' in secret_data:
        cert_key = 'cert' if 'cert' in secret_data else 'tls.crt'
        custom_cert = base64.b64decode(secret_data[cert_key]).decode('utf-8')
        logger.info(f"Found certificate in credentials secret (key: {cert_key})")
    
    if 'key' in secret_data or 'tls.key' in secret_data:
        key_key = 'key' if 'key' in secret_data else 'tls.key'
        custom_key = base64.b64decode(secret_data[key_key]).decode('utf-8')
        logger.info(f"Found key in credentials secret (key: {key_key})")
    
    # Extract username/password credentials
    if 'username' in secret_data:
        username = base64.b64decode(secret_data['username']).decode('utf-8')
        logger.info("Found username in credentials secret")
    
    if 'password' in secret_data:
        password = base64.b64decode(secret_data['password']).decode('utf-8')
        logger.info("Found password in credentials secret")
    
    # Log authentication method detection - username/password takes precedence
    if username and password:
        logger.info("Using username/password (Basic Auth) authentication")
    elif custom_cert and custom_key:
        logger.info("Using certificate-based (mTLS) authentication")
    else:
        logger.warning("No complete authentication credentials found")
    
    return custom_cert, custom_key, username, password


def generate_cli_toml(domain: str, auth_type: str = "cert", username: str = None, password: str = None) -> str:
    """
    Generate the CLI TOML configuration content.
    
    Args:
        domain: The Pulp domain name
        auth_type: "cert" for certificate-based auth, "basic" for username/password
        username: Username for basic auth (required if auth_type="basic")
        password: Password for basic auth (required if auth_type="basic")
    
    Returns:
        CLI TOML configuration string
    """
    if auth_type == "basic":
        return f"""[cli]
base_url = "{PULP_API_BASE_URL}"
api_root = "/api/pulp/"
username = "{username if username else ''}"
password = "{password if password else ''}"
domain = "{domain if domain else ''}"
verify_ssl = true
format = "json"
dry_run = false
timeout = 0
verbose = 0
"""
    else:
        return f"""[cli]
base_url = "{PULP_API_BASE_URL}"
api_root = "/api/pulp/"
cert = "./tls.crt"
key = "./tls.key"
domain = "{domain if domain else ''}"
verify_ssl = true
format = "json"
dry_run = false
timeout = 0
verbose = 0
"""


def create_pulp_domain(
    domain: str,
    cert: str = None,
    key: str = None,
    username: str = None,
    password: str = None,
    logger = None
) -> bool:
    """
    Create a Pulp domain via the API.
    
    Supports both certificate-based (mTLS) and Basic Auth authentication.
    If cert/key are provided, uses mTLS. Otherwise falls back to Basic Auth.
    
    Args:
        domain: The domain name to create
        cert: TLS certificate content (for mTLS)
        key: TLS key content (for mTLS)
        username: Username (for Basic Auth)
        password: Password (for Basic Auth)
        logger: Logger instance
    
    Returns:
        True if domain was created or already exists, False otherwise
    """
    use_basic_auth = username and password
    auth_method = "Basic Auth" if use_basic_auth else "certificate"
    logger.info(f"Creating domain '{domain}' via Pulp API with {auth_method} authentication")
    
    try:
        domain_data = {"name": domain}
        
        if use_basic_auth:
            response = requests.post(
                f"{PULP_API_BASE_URL}/api/pulp/create-domain/",
                json=domain_data,
                auth=(username, password),
                verify=True
            )
        elif cert and key:
            with temp_cert_files(cert, key) as (cert_path, key_path):
                response = requests.post(
                    f"{PULP_API_BASE_URL}/api/pulp/create-domain/",
                    json=domain_data,
                    cert=(cert_path, key_path),
                    verify=True
                )
        else:
            logger.error(f"No valid credentials provided for domain '{domain}'")
            return False
        
        if response.status_code == 201:
            logger.info(f"Domain '{domain}' created successfully via API")
            return True
        elif response.status_code == 400 and "already exists" in response.text:
            logger.warning(f"Domain '{domain}' already exists")
            return True
        else:
            logger.error(f"Failed to create domain '{domain}': {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error creating domain '{domain}': {str(e)}")
        return False


def build_pulp_access_secret_data(
    domain: str,
    custom_cert: Optional[str],
    custom_key: Optional[str],
    username: Optional[str],
    password: Optional[str],
    logger
) -> dict:
    """
    Build the data for the pulp-access Kubernetes secret.
    
    Supports both username/password (Basic Auth) and certificate-based (mTLS) authentication.
    If username/password are provided, they take precedence.
    
    Args:
        domain: The Pulp domain name
        custom_cert: TLS certificate content (for mTLS)
        custom_key: TLS key content (for mTLS)
        username: Username (for Basic Auth)
        password: Password (for Basic Auth)
        logger: Logger instance
    
    Returns:
        Dictionary containing the secret data
    """
    use_basic_auth = username and password
    
    if use_basic_auth:
        cli_toml_content = generate_cli_toml(domain, auth_type="basic", username=username, password=password)
        logger.info("Building secret with Basic Auth authentication")
    elif custom_cert and custom_key:
        cli_toml_content = generate_cli_toml(domain, auth_type="cert")
        logger.info("Building secret with certificate-based authentication")
    else:
        cli_toml_content = generate_cli_toml(domain, auth_type="basic", username=username, password=password)
        logger.info("Building secret with incomplete credentials")
    
    encoded_cli_toml = base64.b64encode(cli_toml_content.encode('utf-8')).decode('utf-8')
    secret_data = {"cli.toml": encoded_cli_toml}
    
    if use_basic_auth:
        secret_data["username"] = base64.b64encode(username.encode('utf-8')).decode('utf-8')
        logger.info("Adding username to secret")
        secret_data["password"] = base64.b64encode(password.encode('utf-8')).decode('utf-8')
        logger.info("Adding password to secret")
    elif custom_cert and custom_key:
        secret_data["tls.crt"] = base64.b64encode(custom_cert.encode('utf-8')).decode('utf-8')
        logger.info("Adding custom certificate to secret")
        secret_data["tls.key"] = base64.b64encode(custom_key.encode('utf-8')).decode('utf-8')
        logger.info("Adding custom key to secret")
    
    if domain:
        secret_data["domain"] = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
        logger.info(f"Adding domain '{domain}' to secret")
    
    return secret_data


def create_kubernetes_secret(
    api: kubernetes.client.CoreV1Api,
    namespace: str,
    secret_name: str,
    secret_data: dict,
    owner_ref: kubernetes.client.V1OwnerReference,
    logger
) -> None:
    """Create a Kubernetes secret with the given data."""
    secret = kubernetes.client.V1Secret(
        metadata=kubernetes.client.V1ObjectMeta(
            name=secret_name,
            namespace=namespace,
            owner_references=[owner_ref]
        ),
        type="Opaque",
        data=secret_data
    )
    
    api.create_namespaced_secret(namespace=namespace, body=secret)
    logger.info(f"Secret '{secret_name}' created in namespace '{namespace}'")


def create_image_repository(
    custom_api: kubernetes.client.CustomObjectsApi,
    namespace: str,
    owner_ref: kubernetes.client.V1OwnerReference,
    logger
) -> None:
    """Create an ImageRepository custom resource."""
    imagerepo_body = {
        "apiVersion": "appstudio.redhat.com/v1alpha1",
        "kind": "ImageRepository",
        "metadata": {
            "name": IMAGE_REPO_NAME,
            "namespace": namespace,
            "ownerReferences": [owner_ref]
        },
        "spec": {
            "image": {
                "name": "pulp-automatic-repository",
                "visibility": "private"
            }
        }
    }
    
    custom_api.create_namespaced_custom_object(
        group="appstudio.redhat.com",
        version="v1alpha1",
        namespace=namespace,
        plural="imagerepositories",
        body=imagerepo_body
    )
    logger.info(f"ImageRepository '{IMAGE_REPO_NAME}' created in namespace '{namespace}'")


def extract_quay_credentials_from_secret(
    api: kubernetes.client.CoreV1Api,
    namespace: str,
    secret_name: str,
    logger
) -> Optional[Tuple[str, str, str]]:
    """
    Extract Quay credentials from the generated ImageRepository secret.
    Returns (username, password, repository) or None if extraction fails.
    """
    try:
        generated_secret = api.read_namespaced_secret(secret_name, namespace)
        
        if not (generated_secret.data and '.dockerconfigjson' in generated_secret.data):
            logger.warning(f"No .dockerconfigjson found in secret '{secret_name}'")
            return None
        
        docker_config_encoded = generated_secret.data['.dockerconfigjson']
        docker_config_decoded = base64.b64decode(docker_config_encoded).decode('utf-8')
        docker_config = json.loads(docker_config_decoded)
        
        if not ('auths' in docker_config and docker_config['auths']):
            logger.warning("No 'auths' found in docker config")
            return None
        
        registry_url = list(docker_config['auths'].keys())[0]
        auth_data = docker_config['auths'][registry_url]
        
        if not registry_url.startswith('quay.io/'):
            logger.warning(f"Registry URL doesn't start with quay.io/: {registry_url}")
            return None
        
        repository = registry_url[len('quay.io/'):]
        logger.info(f"Extracted pulp_quay_repository: {repository}")
        
        if 'auth' not in auth_data:
            logger.warning(f"No 'auth' field found in auth data for {registry_url}")
            return None
        
        auth_token = auth_data['auth']
        decoded_auth = base64.b64decode(auth_token).decode('utf-8')
        
        if ':' not in decoded_auth:
            logger.warning("Auth token doesn't contain ':' separator")
            return None
        
        username, password = decoded_auth.split(':', 1)
        return username, password, repository
        
    except ApiException as e:
        if e.status == 404:
            logger.warning(f"Generated secret '{secret_name}' not found yet in namespace '{namespace}'")
        else:
            logger.error(f"Error reading generated secret '{secret_name}': {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing docker config JSON: {e}")
        return None
    except Exception as e:
        logger.error(f"Error extracting Quay credentials: {e}")
        return None


def configure_quay_backend(
    domain: str,
    quay_username: str,
    quay_password: str,
    repository: str,
    logger,
    cert: str = None,
    key: str = None,
    auth_username: str = None,
    auth_password: str = None
) -> bool:
    """
    Configure Quay as the OCI storage backend for a Pulp domain.
    
    Supports both certificate-based (mTLS) and Basic Auth authentication for the API calls.
    
    Args:
        domain: The Pulp domain name
        quay_username: Quay registry username for OCI storage
        quay_password: Quay registry password for OCI storage
        repository: Quay repository name
        logger: Logger instance
        cert: TLS certificate content (for mTLS API auth)
        key: TLS key content (for mTLS API auth)
        auth_username: Username for Basic Auth API calls
        auth_password: Password for Basic Auth API calls
    
    Returns:
        True if configuration succeeded, False otherwise
    """
    use_basic_auth = auth_username and auth_password
    auth_method = "Basic Auth" if use_basic_auth else "certificate"
    logger.info(f"Configuring OCI storage for domain '{domain}' with repository '{repository}' using {auth_method}")
    
    try:
        def make_request(method, url, **kwargs):
            if use_basic_auth:
                return getattr(requests, method)(url, auth=(auth_username, auth_password), verify=True, **kwargs)
            elif cert and key:
                with temp_cert_files(cert, key) as (cert_path, key_path):
                    return getattr(requests, method)(url, cert=(cert_path, key_path), verify=True, **kwargs)
            else:
                raise ValueError("No valid credentials available for API request")
        
        # Get domain information
        domain_response = make_request(
            'get',
            f"{PULP_API_BASE_URL}/api/pulp/{domain}/api/v3/domains/?name={domain}&offset=0&limit=1"
        )
        
        if domain_response.status_code != 200:
            logger.error(f"Failed to get domain info: {domain_response.status_code}")
            return False
        
        domain_data = domain_response.json()
        if not (domain_data.get('count', 0) > 0 and domain_data.get('results')):
            logger.error(f"Domain '{domain}' not found in API response")
            return False
        
        domain_info = domain_data['results'][0]
        pulp_href = domain_info.get('pulp_href', '')
        
        if not pulp_href:
            logger.error("No pulp_href found in domain info")
            return False
        
        href_parts = pulp_href.rstrip('/').split('/')
        if len(href_parts) < 8:
            logger.error(f"Invalid pulp_href format: {pulp_href}")
            return False
        
        domain_uuid = href_parts[-1]
        logger.info(f"Extracted domain UUID: {domain_uuid}")
        
        # Create OCI storage configuration
        oci_data = {
            "name": domain,
            "pulp_labels": {},
            "storage_class": "pulp_service.app.storage.OCIStorage",
            "storage_settings": {
                "password": quay_password,
                "username": quay_username,
                "repository": repository
            }
        }
        
        # Update domain with OCI storage
        update_response = make_request(
            'put',
            f"{PULP_API_BASE_URL}/api/pulp/{domain}/api/v3/domains/{domain_uuid}/",
            json=oci_data
        )
        
        if update_response.status_code == 202:
            logger.info(f"Successfully configured OCI storage for domain '{domain}'")
            return True
        else:
            logger.error(f"Failed to update domain storage: {update_response.status_code} - {update_response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Error configuring Quay backend: {str(e)}")
        return False


def update_status(
    custom_api: kubernetes.client.CustomObjectsApi,
    namespace: str,
    name: str,
    status: dict,
    logger
) -> None:
    """Update the status of a PulpAccessRequest."""
    try:
        custom_api.patch_namespaced_custom_object_status(
            group="pulp.konflux-ci.dev",
            version="v1alpha1",
            namespace=namespace,
            plural="pulpaccessrequests",
            name=name,
            body={'status': status}
        )
        logger.info("Status updated successfully")
    except Exception as e:
        logger.error(f"Failed to update status: {e}")


def validate_credentials_secret(
    api: kubernetes.client.CoreV1Api,
    credentials_secret_name: str,
    namespace: str,
    status: StatusTracker,
    logger
) -> kubernetes.client.V1Secret:
    """Validate and retrieve the credentials secret."""
    if not credentials_secret_name:
        logger.error("credentialsSecretName not provided in spec")
        status.add_condition('Ready', 'False', 'MissingCredentials', 'credentialsSecretName is required')
        raise kopf.PermanentError("credentialsSecretName is required")
    
    try:
        return api.read_namespaced_secret(credentials_secret_name, namespace)
    except ApiException as e:
        if e.status == 404:
            logger.error(f"Credentials secret '{credentials_secret_name}' not found in namespace '{namespace}'")
            status.add_condition('Ready', 'False', 'SecretNotFound', f"Credentials secret '{credentials_secret_name}' not found")
            raise kopf.TemporaryError(f"Secret '{credentials_secret_name}' not found", delay=30)
        else:
            logger.error(f"Error reading credentials secret: {e}")
            status.add_condition('Ready', 'False', 'SecretReadError', f"Error reading credentials secret: {str(e)}")
            raise


def is_already_processed(body: dict, logger) -> bool:
    """Check if the PulpAccessRequest has already been processed successfully."""
    existing_status = body.get('status', {})
    if existing_status.get('conditions'):
        for condition in existing_status.get('conditions', []):
            if condition.get('type') == 'Ready' and condition.get('status') == 'True':
                logger.info("PulpAccessRequest already processed successfully, skipping")
                return True
    return False


@kopf.on.create('pulp.konflux-ci.dev', 'v1alpha1', 'pulpaccessrequests')
def create_secret(body, spec, namespace, logger, patch, **kwargs):
    """Main handler for PulpAccessRequest creation."""
    api = kubernetes.client.CoreV1Api()
    custom_api = kubernetes.client.CustomObjectsApi()
    
    # Check if already processed
    if is_already_processed(body, logger):
        return
    
    # Initialize status tracking
    status = StatusTracker()
    resource_name = body['metadata']['name']
    
    try:
        # Validate and get credentials secret
        credentials_secret_name = spec.get('credentialsSecretName', None)
        credentials_secret = validate_credentials_secret(
            api, credentials_secret_name, namespace, status, logger
        )
        
        # Extract credentials (supports both cert/key and username/password)
        secret_data = credentials_secret.data or {}
        custom_cert, custom_key, auth_username, auth_password = extract_credentials_from_secret(secret_data, logger)
        
        # Determine authentication method - username/password takes precedence
        has_valid_auth = (auth_username and auth_password) or (custom_cert and custom_key)
        
        # Generate domain name
        domain = f"konflux-{namespace}"
        logger.info(f"Generated domain name: {domain}")
        status.data['domain'] = domain
        
        # Create Pulp domain if we have valid credentials
        if domain and has_valid_auth:
            status.data['domainCreated'] = create_pulp_domain(
                domain,
                cert=custom_cert,
                key=custom_key,
                username=auth_username,
                password=auth_password,
                logger=logger
            )
        elif domain:
            logger.warning("Cannot create domain: either certificate/key or username/password are required")
        
        # Build and create the pulp-access secret
        owner_ref = create_owner_reference(body)
        pulp_secret_data = build_pulp_access_secret_data(
            domain, custom_cert, custom_key, auth_username, auth_password, logger
        )
        create_kubernetes_secret(api, namespace, PULP_ACCESS_SECRET_NAME, pulp_secret_data, owner_ref, logger)
        
        # Configure Quay backend if requested
        use_quay_backend = spec.get('use_quay_backend', False)
        if use_quay_backend:
            # Create ImageRepository
            create_image_repository(custom_api, namespace, owner_ref, logger)
            status.data['imageRepositoryCreated'] = True
            
            # Wait for the ImageRepository controller to create the secret
            time.sleep(15)
            
            # Extract Quay credentials and configure backend
            image_repo_secret_name = f"{IMAGE_REPO_NAME}{IMAGE_REPO_SECRET_SUFFIX}"
            quay_creds = extract_quay_credentials_from_secret(api, namespace, image_repo_secret_name, logger)
            
            if quay_creds and has_valid_auth:
                quay_username, quay_password, repository = quay_creds
                status.data['quayBackendConfigured'] = configure_quay_backend(
                    domain=domain,
                    quay_username=quay_username,
                    quay_password=quay_password,
                    repository=repository,
                    logger=logger,
                    cert=custom_cert,
                    key=custom_key,
                    auth_username=auth_username,
                    auth_password=auth_password
                )
        else:
            logger.info("Skipping ImageRepository creation and OCI storage configuration - use_quay_backend is False")
        
        # Update status to indicate success
        status.add_condition('Ready', 'True', 'SecretCreated', f"Successfully created secret '{PULP_ACCESS_SECRET_NAME}'")
        logger.info("PulpAccessRequest processing completed successfully")
        update_status(custom_api, namespace, resource_name, status.data, logger)
        
    except ApiException as e:
        if e.status == 409:
            if "Secret" in str(e) or "secret" in str(e):
                logger.warning(f"Secret '{PULP_ACCESS_SECRET_NAME}' already exists.")
                status.add_condition('Ready', 'True', 'SecretExists', f"Secret '{PULP_ACCESS_SECRET_NAME}' already exists")
            else:
                logger.warning(f"ImageRepository '{IMAGE_REPO_NAME}' already exists.")
                status.data['imageRepositoryCreated'] = True
                status.add_condition('Ready', 'True', 'ImageRepositoryExists', 'ImageRepository already exists')
        else:
            status.add_condition('Ready', 'False', 'ApiError', f"API error: {str(e)}")
        update_status(custom_api, namespace, resource_name, status.data, logger)
        
    except kopf.PermanentError:
        update_status(custom_api, namespace, resource_name, status.data, logger)
        raise
        
    except kopf.TemporaryError:
        update_status(custom_api, namespace, resource_name, status.data, logger)
        raise
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        status.add_condition('Ready', 'False', 'UnexpectedError', f"Unexpected error: {str(e)}")
        update_status(custom_api, namespace, resource_name, status.data, logger)


@kopf.on.update('pulp.konflux-ci.dev', 'v1alpha1', 'pulpaccessrequests')
def update_pulp_access_request(body, spec, old, new, namespace, logger, **kwargs):
    """Handler for PulpAccessRequest updates - updates the Kubernetes secret."""
    api = kubernetes.client.CoreV1Api()
    custom_api = kubernetes.client.CustomObjectsApi()
    
    resource_name = body['metadata']['name']
    status = StatusTracker()
    
    # Preserve existing status data
    existing_status = body.get('status', {})
    status.data['domain'] = existing_status.get('domain')
    status.data['domainCreated'] = existing_status.get('domainCreated', False)
    status.data['imageRepositoryCreated'] = existing_status.get('imageRepositoryCreated', False)
    status.data['quayBackendConfigured'] = existing_status.get('quayBackendConfigured', False)
    
    logger.info(f"Processing update for PulpAccessRequest '{resource_name}'")
    
    try:
        # Get the credentials secret
        credentials_secret_name = spec.get('credentialsSecretName')
        credentials_secret = validate_credentials_secret(
            api, credentials_secret_name, namespace, status, logger
        )
        
        # Extract credentials (supports both cert/key and username/password)
        secret_data = credentials_secret.data or {}
        custom_cert, custom_key, auth_username, auth_password = extract_credentials_from_secret(secret_data, logger)
        
        # Domain name based on namespace
        domain = f"konflux-{namespace}"
        status.data['domain'] = domain
        
        # Build updated secret data
        pulp_secret_data = build_pulp_access_secret_data(
            domain, custom_cert, custom_key, auth_username, auth_password, logger
        )
        
        # Update the pulp-access secret
        try:
            existing_secret = api.read_namespaced_secret(PULP_ACCESS_SECRET_NAME, namespace)
            existing_secret.data = pulp_secret_data
            api.replace_namespaced_secret(PULP_ACCESS_SECRET_NAME, namespace, existing_secret)
            logger.info(f"Secret '{PULP_ACCESS_SECRET_NAME}' updated in namespace '{namespace}'")
        except ApiException as e:
            if e.status == 404:
                # Secret doesn't exist, create it
                owner_ref = create_owner_reference(body)
                create_kubernetes_secret(api, namespace, PULP_ACCESS_SECRET_NAME, pulp_secret_data, owner_ref, logger)
            else:
                raise
        
        status.add_condition('Ready', 'True', 'Updated', f"Secret '{PULP_ACCESS_SECRET_NAME}' updated successfully")
        update_status(custom_api, namespace, resource_name, status.data, logger)
        logger.info("PulpAccessRequest update completed successfully")
        
    except (kopf.PermanentError, kopf.TemporaryError):
        update_status(custom_api, namespace, resource_name, status.data, logger)
        raise
        
    except Exception as e:
        logger.error(f"Unexpected error during update: {str(e)}")
        status.add_condition('Ready', 'False', 'UpdateError', f"Unexpected error: {str(e)}")
        update_status(custom_api, namespace, resource_name, status.data, logger)


@kopf.on.delete('pulp.konflux-ci.dev', 'v1alpha1', 'pulpaccessrequests')
def delete_pulp_access_request(body, namespace, logger, **kwargs):
    """Handler for PulpAccessRequest deletion - cleans up created resources."""
    api = kubernetes.client.CoreV1Api()
    custom_api = kubernetes.client.CustomObjectsApi()
    
    resource_name = body['metadata']['name']
    logger.info(f"Processing deletion for PulpAccessRequest '{resource_name}'")
    
    # Delete the pulp-access secret
    try:
        api.delete_namespaced_secret(PULP_ACCESS_SECRET_NAME, namespace)
        logger.info(f"Secret '{PULP_ACCESS_SECRET_NAME}' deleted from namespace '{namespace}'")
    except ApiException as e:
        if e.status == 404:
            logger.info(f"Secret '{PULP_ACCESS_SECRET_NAME}' not found, already deleted")
        else:
            logger.error(f"Error deleting secret '{PULP_ACCESS_SECRET_NAME}': {e}")
    
    # Delete the ImageRepository if it was created
    existing_status = body.get('status', {})
    if existing_status.get('imageRepositoryCreated', False):
        try:
            custom_api.delete_namespaced_custom_object(
                group="appstudio.redhat.com",
                version="v1alpha1",
                namespace=namespace,
                plural="imagerepositories",
                name=IMAGE_REPO_NAME
            )
            logger.info(f"ImageRepository '{IMAGE_REPO_NAME}' deleted from namespace '{namespace}'")
        except ApiException as e:
            if e.status == 404:
                logger.info(f"ImageRepository '{IMAGE_REPO_NAME}' not found, already deleted")
            else:
                logger.error(f"Error deleting ImageRepository '{IMAGE_REPO_NAME}': {e}")
    
    logger.info(f"PulpAccessRequest '{resource_name}' cleanup completed")

