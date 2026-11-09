"""Shared Firestore client helper, used by the metadata handlers."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

from google.cloud import firestore


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
