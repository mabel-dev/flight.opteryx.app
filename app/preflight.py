"""What this service must be able to reach before it is allowed to serve.

Run from the Dockerfile's CMD, ahead of the server, so an instance that cannot
reach its dependencies exits the container non-zero without ever opening a
port. On Cloud Run that fails the revision, so a broken build cannot swap out a
working one. See `opteryx_shared_services.preflight` for why that guarantee
cannot live in the ASGI lifespan alone.

This file is only the declaration -- the engine, the probe shapes and the
alerting are shared across the fleet.
"""

import sys

from opteryx_shared_services.preflight import Preflight
from opteryx_shared_services.preflight import firestore_read
from opteryx_shared_services.preflight import gcs_list
from opteryx_shared_services.preflight import secret_manager

preflight = Preflight(
    component="flight",
    checks=(
        secret_manager(),
        # `personal` is the workspace collection a Flight client resolves
        # against; the configuration document shares the `(default)` database.
        firestore_read("firestore-personal", collection="personal"),
        firestore_read(
            "firestore-catalog",
            collection="$catalog",
            database_key="FIRESTORE_DATABASE",
            covered_by="firestore-personal",
        ),
        # Data is read out of the bucket to satisfy a DoGet. Read, so LIST.
        gcs_list("gcs-data", bucket_key=("DATA_BUCKET", "GCS_BUCKET")),
    ),
)

__all__ = ["preflight"]


if __name__ == "__main__":
    sys.exit(preflight.main())
