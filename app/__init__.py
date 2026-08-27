# Importing the config client here, in the package `__init__`, is deliberate:
# it is the earliest hook the service has. Python runs this file before the
# body of any `app.*` module, so the configuration document is read and copied
# into `os.environ` before anything in the service can import `opteryx` or
# `opteryx_catalog`. Both bind their settings into module-level constants at
# import and never re-read them, so a promotion one import too late is a
# promotion that changes nothing.
from opteryx_shared_services import config  # noqa: F401
from opteryx_shared_services.logging import set_log_name

# Every record this service emits is named `opteryx.flight`. Set before anything
# has called `get_logger()` -- the name is bound when the logger is first
# configured, and a later change would leave earlier records under the default.
set_log_name("opteryx.flight")

