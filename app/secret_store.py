"""Read-only lookup of JWT signing *public* keys from GCP Secret Manager.

The auth service publishes each day's public key as a version of the secret
`<YYYYMMDD>-public`, with a JSON payload `{"kid": ..., "pem": ..., "expires": ...}`.
This service only ever reads those public halves; it never creates secrets
and never reads private key material.

The project is taken from `GCP_PROJECT_ID`, `GCP_PROJECT` or
`GOOGLE_CLOUD_PROJECT`, falling back to the GCE/Cloud Run metadata server.
"""

import datetime
import json
import os
from functools import lru_cache
from typing import Optional

import requests
from google.api_core import exceptions as gcp_exceptions  # type: ignore
from google.cloud import secretmanager  # type: ignore
from opteryx.utils.dates import parse_iso


@lru_cache(maxsize=1)
def _metadata_project() -> Optional[str]:
    """Try to retrieve the project-id from GCE/Cloud Run metadata server.

    Returns None if metadata is not reachable or the request fails.
    """
    try:
        # Metadata server requires the header Metadata-Flavor: Google
        r = requests.get(
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            headers={"Metadata-Flavor": "Google"},
            timeout=0.5,
        )
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        return None
    return None


@lru_cache(maxsize=1)
def _detect_project() -> Optional[str]:
    """Return the GCP project id string from common environment variables.

    Checks common variants used in the repo: `GCP_PROJECT_ID`, `GCP_PROJECT`, and
    `GOOGLE_CLOUD_PROJECT`.
    """
    env = (
        os.environ.get("GCP_PROJECT_ID")
        or os.environ.get("GCP_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
    )
    if env:
        return env
    # Fall back to metadata server if available
    return _metadata_project()


@lru_cache(maxsize=1)
def get_secret_backend() -> tuple[str, Optional[object], Optional[str]]:
    """Return (backend_name, client, project) for the secret store.

    This factory abstracts the creation of a backend client (GCP SME client)
    from the store/load logic. The backend name is either 'gcp' or 'fs'. The
    client is either the GCP Secret Manager client or None. The project value
    is the resolved GCP project id.
    """
    project = _detect_project()
    if not project:
        raise RuntimeError(
            "GCP project could not be detected. Ensure GCP_PROJECT.* env vars are set or metadata server is reachable."
        )
    client = secretmanager.SecretManagerServiceClient()
    return ("gcp", client, project)


def _date_secret_id_for_kid(kid: str, suffix: str) -> str:
    """Return a secret id string for the daily secret corresponding to `kid` and suffix.

    For example, kid=20251126 and suffix=private -> '20251126-private'.
    """
    # Validate format; if invalid, fall back to today's date string
    try:
        _ = datetime.datetime.strptime(kid, "%Y%m%d")
        return f"{kid}-{suffix}"
    except Exception:
        return f"{datetime.date.today().strftime('%Y%m%d')}-{suffix}"


@lru_cache(maxsize=16)  # the kid window in app.auth.deps spans ~9 dates
def load_public_key(kid: str) -> Optional[str]:
    """Load only the public key (PEM) for `kid`.

    Returns the public PEM string, or None when no enabled, unexpired
    version carries this `kid`.
    """
    _, client, project = get_secret_backend()

    pub_secret_id = _date_secret_id_for_kid(kid, "public")
    parent = f"projects/{project}/secrets/{pub_secret_id}"
    # List versions; if resource is missing, do not attempt to create it
    try:
        versions = client.list_secret_versions(request={"parent": parent})
    except gcp_exceptions.NotFound:
        return None
    except gcp_exceptions.GoogleAPICallError:
        return None

    vers = [v for v in versions]
    try:
        vers.sort(key=lambda v: v.create_time, reverse=True)
    except Exception:
        pass
    for v in vers:
        if getattr(v, "state", None) and getattr(v.state, "name", "") != "ENABLED":
            continue
        try:
            raw = client.access_secret_version(request={"name": v.name}).payload.data
        except gcp_exceptions.GoogleAPICallError:
            continue
        try:
            payload = raw.decode()
        except UnicodeDecodeError:
            # fallback if decoding fails
            continue
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if data.get("kid") != kid:
            continue
        expires = data.get("expires")
        if expires:
            exp_dt = parse_iso(expires)
            if exp_dt and exp_dt < datetime.datetime.utcnow():
                continue
        return data.get("pem")
    return None
