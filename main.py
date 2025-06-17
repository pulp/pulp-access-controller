import kopf
import kubernetes.client
from kubernetes.client.rest import ApiException
import base64
import os

@kopf.on.create('pulp.konflux-ci.dev', 'v1alpha1', 'pulpaccessrequests')
def create_secret(body, spec, namespace, logger, **kwargs):
    cert = os.getenv('pulp_cert')
    key = os.getenv('pulp_key')
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

    if not cert or not key:
        raise kopf.PermanentError("Both 'pulp_cert' and 'pulp_key' environment variables must be provided.")

    secret_name = "pulp-access"

    # Encode as base64 (Secrets require this)
    encoded_cert = base64.b64encode(cert.encode('utf-8')).decode('utf-8')
    encoded_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')
    encoded_cli_toml = base64.b64encode(cli_toml_content.encode('utf-8')).decode('utf-8')

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
        data={
            "tls.crt": encoded_cert,
            "tls.key": encoded_key,
            "cli.toml": encoded_cli_toml,
        }
    )

    api = kubernetes.client.CoreV1Api()
    try:
        api.create_namespaced_secret(namespace=namespace, body=secret)
        logger.info(f"Secret '{secret_name}' created in namespace '{namespace}'")
    except ApiException as e:
        if e.status == 409:
            logger.warning(f"Secret '{secret_name}' already exists.")
        else:
            raise