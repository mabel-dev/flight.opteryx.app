"""Shared Firestore client helper, used by the metadata handlers."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

from google.cloud import firestore
from opteryx_shared_services.config import get_config


@lru_cache(maxsize=1)
def _get_firestore_client(
    project: Optional[str] = None, database: Optional[str] = None
) -> Optional[firestore.Client]:
    """Return a Firestore client for the current project/database, or None on error.

    If ``project`` is not provided the function will attempt to infer it from
    environment variables (GCP_PROJECT, GCP_PROJECT_ID, GOOGLE_CLOUD_PROJECT).
    ``database`` defaults to the accounts database, ``CLIENTS_FIRESTORE_DATABASE``.
    On any exception, None is returned so higher-level code can fall back
    to treating Firestore as a dependent service that is unavailable.
    """
    try:
        proj = project or (
            os.environ.get("GCP_PROJECT")
            or os.environ.get("GCP_PROJECT_ID")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
        )
        client_kwargs = {"database": database or get_config("CLIENTS_FIRESTORE_DATABASE", "(default)")}
        if proj:
            client_kwargs["project"] = proj
        return firestore.Client(**client_kwargs)
    except Exception:
        return None
