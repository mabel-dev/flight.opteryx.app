"""Process entrypoint: `python -m app.main`.

Unlike odata.opteryx, the process itself *is* the server -- there's no
ASGI/uvicorn layer. `FlightServerBase` starts serving as soon as it's
constructed (per its own docstring); `serve()` just blocks until shutdown.

Binds insecure `grpc://` on `$PORT`: Cloud Run terminates TLS at its front
end and forwards h2c (plaintext HTTP/2) to the container, same as any other
`--use-http2` Cloud Run service (see docs/design.md, "Deployment").
"""

from __future__ import annotations

import os

from app.flight.server import OpteryxFlightServer
from opteryx_shared_services.logging import get_logger
from opteryx_shared_services.logging import set_log_name

set_log_name("opteryx.flight")
logger = get_logger()
logger.setLevel(5)


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    location = f"grpc://0.0.0.0:{port}"

    server = OpteryxFlightServer(location=location)
    logger.info(f"opteryx.flight listening on {location}")
    server.serve()


if __name__ == "__main__":
    main()
