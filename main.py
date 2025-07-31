import kopf
import kubernetes.client
from kubernetes.client.rest import ApiException
from pulp_oauth2_auth import PulpOAuth2Session
import base64
import os

@kopf.on.create('pulp.konflux-ci.dev', 'v1alpha1', 'pulpaccessrequests')
def create_secret(body, spec, namespace, logger, **kwargs):
    cert = os.getenv('pulp_cert')
    key = os.getenv('pulp_key')
    
    # Extract optional client_id and client_secret from spec
    client_id = spec.get('client_id', None)
    client_secret = spec.get('client_secret', None)
    domain = spec.get('domain', None)
    
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
verify_ssl = true
format = "json"
dry_run = false
timeout = 0
verbose = 0
"""

    secret_name = "pulp-access"

    # Encode as base64 (Secrets require this)
    encoded_cert = base64.b64encode(cert.encode('utf-8')).decode('utf-8')
    encoded_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')
    encoded_cli_toml = base64.b64encode(cli_toml_content.encode('utf-8')).decode('utf-8')

    # Prepare secret data with mandatory fields
    secret_data = {
        "tls.crt": encoded_cert,
        "tls.key": encoded_key,
        "cli.toml": encoded_cli_toml,
    }
    
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
    if domain and client_id and client_secret:
        try:
            
            logger.info(f"Creating domain '{domain}' via Pulp API")
            session = PulpOAuth2Session(
                client_id=client_id,
                client_secret=client_secret,
                base_url="https://console.redhat.com"
            )
            
            # Create domain via POST request
            domain_data = {"name": domain}
            response = session.post("/api/pulp/create-domain/", json=domain_data)
            
            if response.status_code == 201:
                logger.info(f"Domain '{domain}' created successfully via API")
            elif response.status_code == 400 and "already exists" in response.text:
                logger.warning(f"Domain '{domain}' already exists")
            else:
                logger.error(f"Failed to create domain '{domain}': {response.status_code} - {response.text}")
                
        except ImportError:
            logger.error("pulp_oauth2_auth module not found. Ensure pulp_oauth2_auth.py is in the same directory as main.py")
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

    api = kubernetes.client.CoreV1Api()
    try:
        api.create_namespaced_secret(namespace=namespace, body=secret)
        logger.info(f"Secret '{secret_name}' created in namespace '{namespace}'")
        
        # If domain and OAuth credentials are provided, create the domain via API
        
        
    except ApiException as e:
        if e.status == 409:
            logger.warning(f"Secret '{secret_name}' already exists.")
        else:
            raise