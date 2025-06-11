import kopf
import kubernetes.client
from kubernetes.client.rest import ApiException
import base64
import os

@kopf.on.create('pulp.konflux-ci.dev', 'v1alpha1', 'pulpaccessrequests')
def create_secret(body, spec, namespace, logger, **kwargs):
    cert = os.getenv('pulp_cert')
    key = os.getenv('pulp_key')

    if not cert or not key:
        raise kopf.PermanentError("Both 'pulp_cert' and 'pulp_key' environment variables must be provided.")

    secret_name = "pulp-access"

    # Encode as base64 (Secrets require this)
    encoded_cert = base64.b64encode(cert.encode('utf-8')).decode('utf-8')
    encoded_key = base64.b64encode(key.encode('utf-8')).decode('utf-8')

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
        type="kubernetes.io/tls",
        data={
            "tls.crt": encoded_cert,
            "tls.key": encoded_key,
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