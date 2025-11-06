import kopf
import kubernetes.client
from kubernetes.client.rest import ApiException
from pulp_oauth2_auth import PulpOAuth2Session
import base64
import os
import time
import json
from datetime import datetime, timezone

@kopf.on.create('pulp.konflux-ci.dev', 'v1alpha1', 'pulpaccessrequests')
def create_secret(body, spec, namespace, logger, patch, **kwargs):
    api = kubernetes.client.CoreV1Api()
    custom_api = kubernetes.client.CustomObjectsApi()
    
    # Check if already processed by looking at existing status
    existing_status = body.get('status', {})
    if existing_status.get('conditions'):
        for condition in existing_status.get('conditions', []):
            if condition.get('type') == 'Ready' and condition.get('status') == 'True':
                logger.info("PulpAccessRequest already processed successfully, skipping")
                return
    
    # Initialize status tracking
    new_status = {
        'secretName': 'pulp-access',
        'domain': None,
        'domainCreated': False,
        'imageRepositoryCreated': False,
        'quayBackendConfigured': False,
        'conditions': []
    }
    
    def add_condition(condition_type, status_value, reason, message):
        """Helper to add a condition to status"""
        condition = {
            'type': condition_type,
            'status': status_value,
            'reason': reason,
            'message': message,
            'lastTransitionTime': datetime.now(timezone.utc).isoformat()
        }
        new_status['conditions'].append(condition)
        return condition
    
    try:
        # Get the secret name from spec
        credentials_secret_name = spec.get('credentialsSecretName', None)
        
        if not credentials_secret_name:
            logger.error("credentialsSecretName not provided in spec")
            add_condition('Ready', 'False', 'MissingCredentials', 'credentialsSecretName is required')
            raise kopf.PermanentError("credentialsSecretName is required")
        
        # Read the credentials secret
        try:
            credentials_secret = api.read_namespaced_secret(credentials_secret_name, namespace)
        except ApiException as e:
            if e.status == 404:
                logger.error(f"Credentials secret '{credentials_secret_name}' not found in namespace '{namespace}'")
                add_condition('Ready', 'False', 'SecretNotFound', f"Credentials secret '{credentials_secret_name}' not found")
                raise kopf.TemporaryError(f"Secret '{credentials_secret_name}' not found", delay=30)
            else:
                logger.error(f"Error reading credentials secret: {e}")
                add_condition('Ready', 'False', 'SecretReadError', f"Error reading credentials secret: {str(e)}")
                raise
        
        # Decode credentials from the secret
        secret_data = credentials_secret.data or {}
        
        # Extract credentials (decode from base64)
        client_id = None
        client_secret = None
        custom_cert = None
        custom_key = None
        
        if 'client_id' in secret_data:
            client_id = base64.b64decode(secret_data['client_id']).decode('utf-8')
            logger.info("Found client_id in credentials secret")
        
        if 'client_secret' in secret_data:
            client_secret = base64.b64decode(secret_data['client_secret']).decode('utf-8')
            logger.info("Found client_secret in credentials secret")
        
        if 'cert' in secret_data or 'tls.crt' in secret_data:
            cert_key = 'cert' if 'cert' in secret_data else 'tls.crt'
            custom_cert = base64.b64decode(secret_data[cert_key]).decode('utf-8')
            logger.info(f"Found certificate in credentials secret (key: {cert_key})")
        
        if 'key' in secret_data or 'tls.key' in secret_data:
            key_key = 'key' if 'key' in secret_data else 'tls.key'
            custom_key = base64.b64decode(secret_data[key_key]).decode('utf-8')
            logger.info(f"Found key in credentials secret (key: {key_key})")
        
        # Extract other optional parameters from spec
        use_quay_backend = spec.get('use_quay_backend', False)
        
        # Generate domain name from namespace: konflux-<namespace>
        domain = f"konflux-{namespace}"
        logger.info(f"Generated domain name: {domain}")
        new_status['domain'] = domain
        
        # mTLS configuration
        cli_toml_content = """[cli]
base_url = "https://mtls.internal.console.redhat.com"
api_root = "/api/pulp/"
cert = "./tls.crt"
key = "./tls.key"
verify_ssl = true
format = "json"
dry_run = false
timeout = 0
verbose = 0
"""

        # OAuth configuration (created only if client credentials are provided)
        oauth_cli_toml_content = f"""[cli]
base_url = "https://console.redhat.com"
api_root = "/api/pulp/"
client_id = "{client_id}"
client_secret = "{client_secret}"
domain = "{domain if domain else ''}"
verify_ssl = true
format = "json"
dry_run = false
timeout = 0
verbose = 0
"""

        secret_name = "pulp-access"

        # Encode as base64 (Secrets require this)
        encoded_cli_toml = base64.b64encode(cli_toml_content.encode('utf-8')).decode('utf-8')

        # Prepare secret data with mandatory fields
        secret_data = {
            "cli.toml": encoded_cli_toml,
        }
        
        # Add custom certificate and key if provided
        if custom_cert:
            encoded_cert = base64.b64encode(custom_cert.encode('utf-8')).decode('utf-8')
            secret_data["tls.crt"] = encoded_cert
            logger.info("Adding custom certificate to secret")
        
        if custom_key:
            encoded_key = base64.b64encode(custom_key.encode('utf-8')).decode('utf-8')
            secret_data["tls.key"] = encoded_key
            logger.info("Adding custom key to secret")
        
        # Add optional client credentials and OAuth TOML if provided
        if client_id:
            encoded_client_id = base64.b64encode(client_id.encode('utf-8')).decode('utf-8')
            secret_data["client_id"] = encoded_client_id
            logger.info(f"Adding client_id to secret")
        
        if client_secret:
            encoded_client_secret = base64.b64encode(client_secret.encode('utf-8')).decode('utf-8')
            secret_data["client_secret"] = encoded_client_secret
            logger.info(f"Adding client_secret to secret")
        
        # Add OAuth TOML configuration if both client credentials are provided
        if client_id and client_secret:
            encoded_oauth_cli_toml = base64.b64encode(oauth_cli_toml_content.encode('utf-8')).decode('utf-8')
            secret_data["oauth-cli.toml"] = encoded_oauth_cli_toml
            logger.info(f"Adding OAuth CLI configuration to secret")
        
        # Add domain if provided
        if domain:
            encoded_domain = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
            secret_data["domain"] = encoded_domain
            logger.info(f"Adding domain '{domain}' to secret")
            
            # Create domain via Pulp API if credentials are available
            if domain and client_id and client_secret:
                try:
                    logger.info(f"Creating domain '{domain}' via Pulp API")
                    session = PulpOAuth2Session(
                        client_id=client_id,
                        client_secret=client_secret,
                        base_url="https://console.redhat.com"
                    )
                    
                    domain_data = {"name": domain}
                    response = session.post("/api/pulp/create-domain/", json=domain_data)
                    
                    if response.status_code == 201:
                        logger.info(f"Domain '{domain}' created successfully via API")
                        new_status['domainCreated'] = True
                    elif response.status_code == 400 and "already exists" in response.text:
                        logger.warning(f"Domain '{domain}' already exists")
                        new_status['domainCreated'] = True
                    else:
                        logger.error(f"Failed to create domain '{domain}': {response.status_code} - {response.text}")
                        
                except Exception as e:
                    logger.error(f"Error creating domain '{domain}': {str(e)}")

        secret = kubernetes.client.V1Secret(
            metadata=kubernetes.client.V1ObjectMeta(
                name=secret_name,
                namespace=namespace,
                owner_references=[kubernetes.client.V1OwnerReference(
                    api_version=body['apiVersion'],
                    kind=body['kind'],
                    name=body['metadata']['name'],
                    uid=body['metadata']['uid'],
                    controller=True,
                    block_owner_deletion=True,
                )]
            ),
            type="Opaque",
            data=secret_data
        )

        api.create_namespaced_secret(namespace=namespace, body=secret)
        logger.info(f"Secret '{secret_name}' created in namespace '{namespace}'")
        
        # Only create ImageRepository and configure OCI storage if use_quay_backend is True
        if use_quay_backend:
            # Create ImageRepository CR
            imagerepo_body = {
                "apiVersion": "appstudio.redhat.com/v1alpha1",
                "kind": "ImageRepository",
                "metadata": {
                    "name": "pulp-access-controller-imagerepo",
                    "namespace": namespace,
                    "ownerReferences": [kubernetes.client.V1OwnerReference(
                        api_version=body['apiVersion'],
                        kind=body['kind'],
                        name=body['metadata']['name'],
                        uid=body['metadata']['uid'],
                        controller=True,
                        block_owner_deletion=True,
                    )]
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
            logger.info(f"ImageRepository 'pulp-access-controller-imagerepo' created in namespace '{namespace}'")
            new_status['imageRepositoryCreated'] = True
            
            # Wait a moment for the ImageRepository controller to create the secret
            time.sleep(15)
            
            # Try to read the generated secret
            secret_name = "pulp-access-controller-imagerepo-image-push"
            try:
                generated_secret = api.read_namespaced_secret(secret_name, namespace)
                
                # Decode and log the docker config
                if not (generated_secret.data and '.dockerconfigjson' in generated_secret.data):
                    logger.warning(f"No .dockerconfigjson found in secret '{secret_name}'")
                    return
                    
                docker_config_encoded = generated_secret.data['.dockerconfigjson']
                docker_config_decoded = base64.b64decode(docker_config_encoded).decode('utf-8')
                
                # Parse the docker config JSON
                docker_config = json.loads(docker_config_decoded)
                
                if not ('auths' in docker_config and docker_config['auths']):
                    logger.warning("No 'auths' found in docker config")
                    return

                # Get the registry URL
                registry_url = list(docker_config['auths'].keys())[0]
                auth_data = docker_config['auths'][registry_url]
                
                # Extract repository path (everything after "quay.io/")
                if not registry_url.startswith('quay.io/'):
                    logger.warning(f"Registry URL doesn't start with quay.io/: {registry_url}")
                    return
                    
                pulp_quay_repository = registry_url[len('quay.io/'):]
                logger.info(f"Extracted pulp_quay_repository: {pulp_quay_repository}")
                
                # Decode the auth token
                if 'auth' not in auth_data:
                    logger.warning(f"No 'auth' field found in auth data for {registry_url}")
                    return
                    
                auth_token = auth_data['auth']
                decoded_auth = base64.b64decode(auth_token).decode('utf-8')
                
                # Split into username and password
                if ':' not in decoded_auth:
                    logger.warning("Auth token doesn't contain ':' separator")
                    return
                    
                username, password = decoded_auth.split(':', 1)
                
                # Configure domain storage with OCI registry credentials
                if domain and client_id and client_secret:
                    logger.info(f"Configuring OCI storage for domain '{domain}' with repository '{pulp_quay_repository}'")
                    
                    config_session = PulpOAuth2Session(
                        client_id=client_id,
                        client_secret=client_secret,
                        base_url="https://console.redhat.com"
                    )
                    
                    # Get domain information
                    domain_response = config_session.get(f"/api/pulp/{domain}/api/v3/domains/?name={domain}&offset=0&limit=1")
                    
                    if domain_response.status_code == 200:
                        domain_data = domain_response.json()
                        if domain_data.get('count', 0) > 0 and domain_data.get('results'):
                            domain_info = domain_data['results'][0]
                            pulp_href = domain_info.get('pulp_href', '')
                            
                            if pulp_href:
                                href_parts = pulp_href.rstrip('/').split('/')
                                if len(href_parts) >= 8:
                                    domain_uuid = href_parts[-1]
                                    logger.info(f"Extracted domain UUID: {domain_uuid}")
                                    
                                    # Create OCI storage configuration
                                    oci_data = {
                                        "name": domain,
                                        "pulp_labels": {},
                                        "storage_class": "pulp_service.app.storage.OCIStorage",
                                        "storage_settings": {
                                            "password": password,
                                            "username": username,
                                            "repository": pulp_quay_repository
                                        }
                                    }
                                    
                                    # Update domain with OCI storage
                                    update_response = config_session.put(
                                        f"/api/pulp/{domain}/api/v3/domains/{domain_uuid}/",
                                        json=oci_data
                                    )
                                    
                                    if update_response.status_code == 202:
                                        logger.info(f"Successfully configured OCI storage for domain '{domain}'")
                                        new_status['quayBackendConfigured'] = True
                                    else:
                                        logger.error(f"Failed to update domain '{domain}' storage: {update_response.status_code} - {update_response.text}")
            except ApiException as secret_e:
                if secret_e.status == 404:
                    logger.warning(f"Generated secret '{secret_name}' not found yet in namespace '{namespace}'")
                else:
                    logger.error(f"Error reading generated secret '{secret_name}': {secret_e}")
            except json.JSONDecodeError as json_e:
                logger.error(f"Error parsing docker config JSON: {json_e}")
            except Exception as parse_e:
                logger.error(f"Error parsing docker config: {parse_e}")
        else:
            logger.info("Skipping ImageRepository creation and OCI storage configuration - use_quay_backend is False")
        
        # Update status to indicate success
        add_condition('Ready', 'True', 'SecretCreated', f"Successfully created secret '{secret_name}'")
        logger.info("PulpAccessRequest processing completed successfully")
        
        # Update status using Kubernetes API directly
        try:
            custom_api.patch_namespaced_custom_object_status(
                group="pulp.konflux-ci.dev",
                version="v1alpha1",
                namespace=namespace,
                plural="pulpaccessrequests",
                name=body['metadata']['name'],
                body={'status': new_status}
            )
            logger.info("Status updated successfully")
        except Exception as status_e:
            logger.error(f"Failed to update status: {status_e}")
        
    except ApiException as e:
        if e.status == 409:
            if "Secret" in str(e) or "secret" in str(e):
                logger.warning(f"Secret '{secret_name}' already exists.")
                add_condition('Ready', 'True', 'SecretExists', f"Secret '{secret_name}' already exists")
            else:
                logger.warning(f"ImageRepository 'pulp-access-controller-imagerepo' already exists.")
                new_status['imageRepositoryCreated'] = True
                add_condition('Ready', 'True', 'ImageRepositoryExists', 'ImageRepository already exists')
        else:
            add_condition('Ready', 'False', 'ApiError', f"API error: {str(e)}")
        
        # Update status in error cases
        try:
            custom_api.patch_namespaced_custom_object_status(
                group="pulp.konflux-ci.dev",
                version="v1alpha1",
                namespace=namespace,
                plural="pulpaccessrequests",
                name=body['metadata']['name'],
                body={'status': new_status}
            )
        except Exception as status_e:
            logger.error(f"Failed to update status: {status_e}")
            
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        add_condition('Ready', 'False', 'UnexpectedError', f"Unexpected error: {str(e)}")
        
        # Update status in error cases
        try:
            custom_api.patch_namespaced_custom_object_status(
                group="pulp.konflux-ci.dev",
                version="v1alpha1",
                namespace=namespace,
                plural="pulpaccessrequests",
                name=body['metadata']['name'],
                body={'status': new_status}
            )
        except Exception as status_e:
            logger.error(f"Failed to update status: {status_e}")
