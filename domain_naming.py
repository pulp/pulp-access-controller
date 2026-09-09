import hashlib
import os
from typing import Optional

import kubernetes.client
from kubernetes.client.rest import ApiException

DOMAIN_NAME_MAX_LENGTH = 50
DOMAIN_PREFIX = "konflux-"
CLUSTER_ID_ENV = "KONFLUX_CLUSTER_ID"
CLUSTER_ID_HASH_LENGTH = 6

_cluster_id_cache: Optional[str] = None


def cluster_id_suffix(cluster_id: str) -> str:
    """Return a short deterministic suffix derived from the cluster ID."""
    return hashlib.sha256(cluster_id.encode()).hexdigest()[:CLUSTER_ID_HASH_LENGTH]


def generate_domain_name(namespace: str, cluster_id: Optional[str] = None) -> str:
    """
    Build a Pulp domain name for a namespace.

    When cluster_id is available: konflux-<namespace>-<hash>
    Otherwise (legacy): konflux-<namespace>
    """
    if not cluster_id:
        return f"{DOMAIN_PREFIX}{namespace}"[:DOMAIN_NAME_MAX_LENGTH]

    suffix = cluster_id_suffix(cluster_id)
    max_namespace_len = DOMAIN_NAME_MAX_LENGTH - len(DOMAIN_PREFIX) - len(suffix) - 1
    truncated_namespace = namespace[:max_namespace_len]
    return f"{DOMAIN_PREFIX}{truncated_namespace}-{suffix}"


def get_cluster_id(logger) -> Optional[str]:
    """
    Resolve the OpenShift cluster ID, cached for the lifetime of the process.

    Precedence:
    1. KONFLUX_CLUSTER_ID environment variable
    2. ClusterVersion (config.openshift.io/v1, name=version) spec.clusterID
    """
    global _cluster_id_cache

    if _cluster_id_cache is not None:
        return _cluster_id_cache or None

    env_cluster_id = os.environ.get(CLUSTER_ID_ENV, "").strip()
    if env_cluster_id:
        _cluster_id_cache = env_cluster_id
        logger.info("Using cluster ID from KONFLUX_CLUSTER_ID environment variable")
        return env_cluster_id

    try:
        custom_api = kubernetes.client.CustomObjectsApi()
        cluster_version = custom_api.get_cluster_custom_object(
            group="config.openshift.io",
            version="v1",
            plural="clusterversions",
            name="version",
        )
        cluster_id = cluster_version.get("spec", {}).get("clusterID", "").strip()
        _cluster_id_cache = cluster_id
        if cluster_id:
            logger.info("Using OpenShift ClusterVersion.spec.clusterID for domain suffix")
        else:
            logger.warning("ClusterVersion has no spec.clusterID; using legacy domain naming")
        return cluster_id or None
    except ApiException as e:
        if e.status == 404:
            logger.info("ClusterVersion not found; using legacy domain naming")
        else:
            logger.warning(f"Could not read ClusterVersion: {e}; using legacy domain naming")
    except Exception as e:
        logger.warning(f"Error reading cluster ID: {e}; using legacy domain naming")

    _cluster_id_cache = ""
    return None


def resolve_domain_name(namespace: str, existing_domain: Optional[str], logger) -> str:
    """
    Return the Pulp domain name for a PulpAccessRequest.

    Domain names are immutable once written to status.domain.
    """
    if existing_domain:
        logger.info(f"Using persisted domain name: {existing_domain}")
        return existing_domain

    cluster_id = get_cluster_id(logger)
    domain = generate_domain_name(namespace, cluster_id)
    logger.info(f"Generated domain name: {domain}")
    return domain
