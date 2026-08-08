"""Secret store abstraction for dev (filesystem) or GCP Secret Manager.

This module provides a minimal interface: `store_key(kid, priv_pem, pub_pem)` and
`load_key(kid)` returning `(priv_pem, pub_pem)` or `None` if missing.

Behavior:
- If the environment indicates a GCP project is present (via `GCP_PROJECT_ID`,
  `GCP_PROJECT` or `GOOGLE_CLOUD_PROJECT`), enable the GCP Secret Manager
  backend. There is no manual override to prefer GCP; use the environment
  to indicate you are running on GCP.

This is intentionally a simple stub — production code should handle
authentication, permissions, secret naming and versions more robustly.
"""

import datetime
import json
import os
from functools import lru_cache
from typing import Optional
from typing import Tuple

import requests
from google.api_core import exceptions as gcp_exceptions  # type: ignore
from google.cloud import secretmanager  # type: ignore
from google.protobuf import timestamp_pb2
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


def list_known_kids() -> list:
    """Return a list of known kids present in the configured secret backend.

    When backend is GCP, iterate secrets in the project and look for daily secrets
    with payloads containing a JSON {"kid":...} and return unique kids. Fails
    noisily if secret manager is not configured.
    """
    _, client, project = get_secret_backend()

    kids = set()

    # List all secrets under the project and inspect their enabled versions for kid payloads
    parent = f"projects/{project}"
    for secret in client.list_secrets(request={"parent": parent}):
        secret_id = secret.name.split("/")[-1]
        # Inspect versions for this secret and find any payloads with a kid key
        versions = client.list_secret_versions(
            request={"parent": f"projects/{project}/secrets/{secret_id}"}
        )
        for v in versions:
            if getattr(v, "state", None) and getattr(v.state, "name", "") != "ENABLED":
                continue
            try:
                payload = client.access_secret_version(
                    request={"name": v.name}
                ).payload.data.decode()
                data = json.loads(payload)
                kk = data.get("kid")
                expires = data.get("expires")
                # Only include if not expired (or if no expiry present).
                # parse_iso returns None if the value isn't date-like, in which
                # case we ignore the expiry and include.
                if expires:
                    exp_dt = parse_iso(expires)
                    if exp_dt and exp_dt < datetime.datetime.utcnow():
                        continue
                if kk:
                    kids.add(kk)
            except Exception:
                continue
    return sorted(kids)


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


def store_key(kid: str, priv_pem: str, pub_pem: str) -> None:
    """Store key material."""
    # Decide backend via factory
    _, client, project = get_secret_backend()
    # Store versions under a daily secret (one secret per kid's date). Each
    # secret version contains JSON {"kid":..., "pem":..., "expires":...}.
    expires_dt = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=4)
    expires_at = expires_dt.isoformat() + "Z"
    ts = timestamp_pb2.Timestamp()
    ts.FromDatetime(expires_dt)
    for suffix, pem in (("private", priv_pem), ("public", pub_pem)):
        secret_id = _date_secret_id_for_kid(kid, suffix)
        parent = f"projects/{project}"
        # Attempt to create the secret resource if it doesn't exist.
        try:
            client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {"replication": {"automatic": {}}, "expire_time": ts},
                }
            )
        except Exception as exc:
            # Only ignore if secret already exists, otherwise let it propagate
            if isinstance(exc, gcp_exceptions.AlreadyExists):
                pass
            else:
                # Re-raise non-AlreadyExists exceptions so callers can detect failures
                raise

        payload = json.dumps({"kid": kid, "pem": pem, "expires": expires_at})

        client.add_secret_version(
            request={
                "parent": f"projects/{project}/secrets/{secret_id}",
                "payload": {"data": payload.encode()},
            }
        )

    return


@lru_cache(maxsize=8)
def load_key(kid: str) -> Optional[Tuple[str, str]]:
    """Load key material for `kid`. Returns (priv_pem, pub_pem) or None."""
    backend, client, project = get_secret_backend()
    # backend, client, project already retrieved; we use them below

    # Look up in the daily secrets for the specified kid. Search versions newest->oldest and
    # only return versions that haven't expired.
    priv_secret_id = _date_secret_id_for_kid(kid, "private")
    pub_secret_id = _date_secret_id_for_kid(kid, "public")
    try:
        # helper to find pem for secret id
        def _find_pem(secret_id: str, desired_kid: str) -> Optional[str]:
            parent = f"projects/{project}/secrets/{secret_id}"
            # list versions
            try:
                versions = client.list_secret_versions(request={"parent": parent})
            except Exception as exc:
                # If the secret resource doesn't exist (NotFound), attempt to create it so future writes succeed
                try:
                    if isinstance(exc, gcp_exceptions.NotFound):
                        parent = f"projects/{project}"
                        # Try to create the two daily secrets (private/public) if missing
                        for suffix in ("private", "public"):
                            secret_id = _date_secret_id_for_kid(kid, suffix)
                            try:
                                # When creating the secret here, set the same expiry into the secret metadata
                                ts_retry = timestamp_pb2.Timestamp()
                                ts_retry.FromDatetime(
                                    datetime.datetime.utcnow() + datetime.timedelta(days=3)
                                )
                                client.create_secret(
                                    request={
                                        "parent": parent,
                                        "secret_id": secret_id,
                                        "secret": {
                                            "replication": {"automatic": {}},
                                            "expire_time": ts_retry,
                                        },
                                    }
                                )
                            except Exception:
                                # ignore any errors creating the resource, best-effort
                                pass
                except Exception:
                    # ignore errors while attempting to create
                    pass
                return None
            # iterate versions (API returns an iterator; convert to list to inspect newest first)
            vers = [v for v in versions]
            # sort by createTime descending if available
            try:
                vers.sort(key=lambda v: v.create_time, reverse=True)
            except Exception:
                pass
            for v in vers:
                if v.state.name != "ENABLED":
                    continue
                ver_name = v.name
                try:
                    payload = client.access_secret_version(
                        request={"name": ver_name}
                    ).payload.data.decode()
                    data = json.loads(payload)
                    if data.get("kid") == desired_kid:
                        expires = data.get("expires")
                        if expires:
                            exp_dt = parse_iso(expires)
                            if exp_dt and exp_dt < datetime.datetime.utcnow():
                                continue
                        return data.get("pem")
                except Exception:
                    continue
            return None

        priv = _find_pem(priv_secret_id, kid)
        pub = _find_pem(pub_secret_id, kid)
        if priv and pub:
            return priv, pub
        return None
    except Exception:
        return None


@lru_cache(maxsize=8)
def load_public_key(kid: str) -> Optional[str]:
    """Load only the public key (PEM) for `kid`.

    This is similar to :func:`load_key`, but it never attempts to create
    secrets if they're missing and only returns the public PEM string or
    None when not found.
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


@lru_cache(maxsize=8)
def find_key_by_kid(kid: str) -> Optional[Tuple[str, str]]:
    """Attempt to find key material for an arbitrary `kid` value by inspecting
    all secrets and versions in the project's secret manager.

    This is a best-effort function that returns (priv_pem, pub_pem) if both
    halves are found for the specified `kid`, or None otherwise.
    """
    _, client, project = get_secret_backend()
    priv = None
    pub = None
    parent = f"projects/{project}"
    for secret in client.list_secrets(request={"parent": parent}):
        secret_id = secret.name.split("/")[-1]
        try:
            versions = client.list_secret_versions(
                request={"parent": f"projects/{project}/secrets/{secret_id}"}
            )
        except gcp_exceptions.GoogleAPICallError:
            continue
        for v in versions:
            try:
                if getattr(v, "state", None) and getattr(v.state, "name", "") != "ENABLED":
                    continue
                payload = client.access_secret_version(
                    request={"name": v.name}
                ).payload.data.decode()
                data = json.loads(payload)
                if data.get("kid") != kid:
                    continue
                expires = data.get("expires")
                if expires:
                    exp_dt = parse_iso(expires)
                    if exp_dt and exp_dt < datetime.datetime.utcnow():
                        continue
                pem = data.get("pem")
                if pem is None:
                    continue
                if secret_id.endswith("-private") or "private" in secret_id:
                    priv = pem
                elif secret_id.endswith("-public") or "public" in secret_id:
                    pub = pem
                # If we've found both, return immediately
                if priv and pub:
                    return priv, pub
            except gcp_exceptions.GoogleAPICallError:
                continue
    return None
