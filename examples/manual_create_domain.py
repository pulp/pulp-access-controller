#!/usr/bin/env python3
"""
Manual test script for the Pulp domain-creation call made by the
pulp-access-controller operator.

This replicates exactly what `create_pulp_domain()` in main.py does:

    POST https://packages.redhat.com/api/pulp/create-domain/
    Body: {"name": "<domain>"}
    Auth: mTLS (client cert/key) OR HTTP Basic Auth (username/password)

Usage examples:

    # Certificate-based (mTLS) auth
    python manual_create_domain.py \\
        --domain konflux-my-namespace \\
        --cert /path/to/tls.crt \\
        --key /path/to/tls.key

    # Basic Auth
    python manual_create_domain.py \\
        --domain konflux-my-namespace \\
        --username myuser --password mypass

    # Also fetch/verify domain info afterwards (like configure_quay_backend does)
    python manual_create_domain.py --domain konflux-my-namespace \\
        --cert tls.crt --key tls.key --verify

    # Read cert/key straight out of a Kubernetes secret (base64-decoded automatically)
    python manual_create_domain.py --domain konflux-my-namespace \\
        --from-secret ./credentials-secret.yaml

    # Just check that credentials/connectivity work at all, via Pulp's built-in
    # 'default' domain (always exists, no create-domain permission required)
    python manual_create_domain.py --check-auth --cert tls.crt --key tls.key
"""

import argparse
import base64
import sys
import tempfile
import os
from contextlib import contextmanager

import requests

# Same constant as main.py in this repo.
PULP_API_BASE_URL = "https://packages.redhat.com"


@contextmanager
def temp_cert_files(cert: str, key: str):
    """Write cert/key PEM strings to temp files, like main.py does."""
    cert_path = key_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".crt", delete=False) as f:
            f.write(cert)
            cert_path = f.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
            f.write(key)
            key_path = f.name
        yield cert_path, key_path
    finally:
        for p in (cert_path, key_path):
            if p and os.path.exists(p):
                os.unlink(p)


def load_cert_key_from_k8s_secret(path: str):
    """
    Very small YAML-free parser for the simple 'stringData: {tls.crt, tls.key}'
    or 'data: {base64...}' shape used in examples/test.yml. Requires PyYAML.
    """
    import yaml

    with open(path) as f:
        doc = yaml.safe_load(f)

    data = doc.get("stringData") or {}
    b64data = doc.get("data") or {}

    def get(key_names, decode=False):
        for k in key_names:
            if k in data:
                return data[k]
            if k in b64data:
                return base64.b64decode(b64data[k]).decode("utf-8")
        return None

    cert = get(["cert", "tls.crt"])
    key = get(["key", "tls.key"])
    username = get(["username"])
    password = get(["password"])
    return cert, key, username, password


def check_auth_via_default_domain(cert: str = None, key: str = None,
                                   username: str = None, password: str = None):
    """
    Sanity-check that the credentials/connectivity are valid at all, without
    needing create-domain permissions. Pulp always has a built-in 'default'
    domain, so we just query it via the same domain-scoped API root the
    controller uses elsewhere (f"{PULP_API_BASE_URL}/api/pulp/{domain}/api/v3/...").

    Useful to isolate "my cert/creds don't work" from "create-domain itself
    is failing/forbidden for this account".
    """
    url = f"{PULP_API_BASE_URL}/api/pulp/default/api/v3/status/"
    print(f"GET {url}  (auth check via the built-in 'default' domain)")

    if username and password:
        print(f"Auth: HTTP Basic ({username})")
        response = requests.get(url, auth=(username, password), verify=True)
    elif cert and key:
        print("Auth: mTLS (client certificate)")
        with temp_cert_files(cert, key) as (cert_path, key_path):
            response = requests.get(url, cert=(cert_path, key_path), verify=True)
    else:
        raise SystemExit("Need either --username/--password or --cert/--key")

    print(f"\nStatus: {response.status_code}")
    try:
        print(f"Response: {response.json()}")
    except ValueError:
        print(f"Response (non-JSON): {response.text[:500]}")

    if response.status_code == 200:
        print("\n✔ Credentials are valid and can reach the Pulp API (via 'default' domain).")
    elif response.status_code in (401, 403):
        print("\n✘ Auth failed/forbidden -- credentials themselves are the problem, "
              "not the create-domain call.")
    else:
        print(f"\n? Unexpected status {response.status_code} -- inspect response above.")

    return response


def create_domain(domain: str, cert: str = None, key: str = None,
                   username: str = None, password: str = None):
    """Mirrors create_pulp_domain() in main.py."""
    url = f"{PULP_API_BASE_URL}/api/pulp/create-domain/"
    payload = {"name": domain}

    print(f"POST {url}")
    print(f"Body: {payload}")

    if username and password:
        print(f"Auth: HTTP Basic ({username})")
        response = requests.post(url, json=payload, auth=(username, password), verify=True)
    elif cert and key:
        print("Auth: mTLS (client certificate)")
        with temp_cert_files(cert, key) as (cert_path, key_path):
            response = requests.post(url, json=payload, cert=(cert_path, key_path), verify=True)
    else:
        raise SystemExit("Need either --username/--password or --cert/--key")

    print(f"\nStatus: {response.status_code}")
    try:
        print(f"Response: {response.json()}")
    except ValueError:
        print(f"Response (non-JSON): {response.text}")

    if response.status_code == 201:
        print(f"\n✔ Domain '{domain}' created.")
    elif response.status_code == 400 and "already exists" in response.text:
        print(f"\n✔ Domain '{domain}' already exists (treated as success by the controller).")
    else:
        print(f"\n✘ Unexpected response creating domain '{domain}'.")

    return response


def verify_domain(domain: str, cert: str = None, key: str = None,
                   username: str = None, password: str = None):
    """
    Mirrors the domain lookup done at the start of configure_quay_backend()
    in main.py -- useful to confirm the domain is visible/queryable after creation.
    """
    url = f"{PULP_API_BASE_URL}/api/pulp/{domain}/api/v3/domains/?name={domain}&offset=0&limit=1"
    print(f"\nGET {url}")

    if username and password:
        response = requests.get(url, auth=(username, password), verify=True)
    else:
        with temp_cert_files(cert, key) as (cert_path, key_path):
            response = requests.get(url, cert=(cert_path, key_path), verify=True)

    print(f"Status: {response.status_code}")
    try:
        data = response.json()
        print(f"Response: {data}")
        if data.get("count", 0) > 0:
            pulp_href = data["results"][0].get("pulp_href", "")
            print(f"\npulp_href: {pulp_href}")
            print(f"domain uuid: {pulp_href.rstrip('/').split('/')[-1]}")
    except ValueError:
        print(f"Response (non-JSON): {response.text}")

    return response


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--domain", required=False, help="Domain name, e.g. konflux-my-namespace (not required with --check-auth)")
    parser.add_argument("--check-auth", action="store_true",
                         help="Skip domain creation; just verify credentials work via Pulp's built-in 'default' domain")

    auth_group = parser.add_argument_group("authentication (choose one method)")
    auth_group.add_argument("--cert", help="Path to client TLS certificate (PEM)")
    auth_group.add_argument("--key", help="Path to client TLS private key (PEM)")
    auth_group.add_argument("--username", help="Basic Auth username")
    auth_group.add_argument("--password", help="Basic Auth password")
    auth_group.add_argument("--from-secret", help="Path to a K8s Secret YAML file to pull cert/key or username/password from")

    parser.add_argument("--verify", action="store_true", help="Also GET the domain afterwards to confirm it's visible via the API")

    args = parser.parse_args()

    cert_pem = key_pem = username = password = None

    if args.from_secret:
        cert_pem, key_pem, username, password = load_cert_key_from_k8s_secret(args.from_secret)
    else:
        if args.cert:
            with open(args.cert) as f:
                cert_pem = f.read()
        if args.key:
            with open(args.key) as f:
                key_pem = f.read()
        username, password = args.username, args.password

    if not ((cert_pem and key_pem) or (username and password)):
        parser.error("Provide --cert/--key, --username/--password, or --from-secret")

    if args.check_auth:
        check_auth_via_default_domain(cert=cert_pem, key=key_pem, username=username, password=password)
        return

    if not args.domain:
        parser.error("--domain is required unless --check-auth is set")

    create_domain(args.domain, cert=cert_pem, key=key_pem, username=username, password=password)

    if args.verify:
        verify_domain(args.domain, cert=cert_pem, key=key_pem, username=username, password=password)


if __name__ == "__main__":
    sys.exit(main())
