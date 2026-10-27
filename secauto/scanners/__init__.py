"""Scanner package: importing this module registers every built-in scanner."""

from .base import BaseScanner, ScanContext, ScannerRegistry, registry, register  # noqa: F401

# Importing the modules below performs @register side effects.
from . import recon  # noqa: F401,E402
from . import subdomains  # noqa: F401,E402
from . import network  # noqa: F401,E402
from . import web  # noqa: F401,E402
from . import tls_extra  # noqa: F401,E402
from . import vuln  # noqa: F401,E402

__all__ = ["BaseScanner", "ScanContext", "ScannerRegistry", "registry", "register"]
