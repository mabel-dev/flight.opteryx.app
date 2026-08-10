# flight.api package

# Importing the config client here, in the package `__init__`, is deliberate:
# it is the earliest hook the service has. Python runs this file before the
# body of any `app.*` module, so the configuration document is read and copied
# into `os.environ` before anything in the service can import `opteryx` or
# `opteryx_catalog`. Both bind their settings into module-level constants at
# import and never re-read them, so a promotion one import too late is a
# promotion that changes nothing.
#
# It cannot simply live next to the `import opteryx` that needs it: several
# modules here already import opteryx above their own
# `from app.config_client import ...`, and isort (float_to_top, third-party
# before first-party) would reorder any call placed by hand between the two.
from app import config_client  # noqa: F401
