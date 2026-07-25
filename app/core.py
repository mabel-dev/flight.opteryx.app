"""
Core helpers used across the app (logger and shared helper functions).

This module provides the minimal surface area needed by the service after
being moved from another repo. It intentionally avoids external runtime
dependencies (other than `logging`) and exposes an `_get_firestore_client`
helper used by both the adapter and routes modules.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

import requests
from google.cloud import firestore


@lru_cache(maxsize=1)
def _runtime_service_account() -> Optional[str]:
    try:
        r = requests.get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
            headers={"Metadata-Flavor": "Google"},
            timeout=0.2,
        )
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        return None
    return None


@lru_cache(maxsize=1)
def _get_firestore_client(
    project: Optional[str] = None, database: Optional[str] = None
) -> Optional[firestore.Client]:
    """Return a Firestore client for the current project/database, or None on error.

    If ``project`` is not provided the function will attempt to infer it from
    environment variables (GCP_PROJECT, GCP_PROJECT_ID, GOOGLE_CLOUD_PROJECT).
    An optional ``database`` parameter is forwarded to ``firestore.Client`` to
    support non-default Firestore databases within the same project.
    On any exception, None is returned so higher-level code can fall back
    to treating Firestore as a dependent service that is unavailable.
    """
    try:
        proj = project or (
            os.environ.get("GCP_PROJECT")
            or os.environ.get("GCP_PROJECT_ID")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
        )
        client_kwargs = {}
        if proj:
            client_kwargs["project"] = proj
        if database is not None:
            client_kwargs["database"] = database
        return firestore.Client(**client_kwargs) if client_kwargs else firestore.Client()
    except Exception:
        return None
