"""Version and product identity for SecAuto."""

__version__ = "1.0.0"
__build__ = "2026.10"

# Product identity
PRODUCT_NAME = "SecAuto"
PRODUCT_TAGLINE = "Autonomous Offensive Security & Reconnaissance Platform"
AUTHOR = "Naman Kumar Sonker"
AUTHOR_INITIALS = "NKS"
ORGANIZATION = "SecAuto Security Labs"
LICENSE = "MIT"
WEBSITE = "https://github.com/nksdev/secauto"

# ASCII banner shown in the terminal
BANNER = r"""
   ███████╗███████╗ ██████╗    █████╗ ██╗   ██╗████████╗ ██████╗
   ██╔════╝██╔════╝██╔════╝   ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗
   ███████╗█████╗  ██║        ███████║██║   ██║   ██║   ██║   ██║
   ╚════██║██╔══╝  ██║        ██╔══██║██║   ██║   ██║   ██║   ██║
   ███████║███████╗╚██████╗   ██║  ██║╚██████╔╝   ██║   ╚██████╔╝
   ╚══════╝╚══════╝ ╚═════╝   ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝
"""

BANNER_SUB = "Autonomous Security Assessment Platform"


def banner_text(color: bool = True) -> str:
    """Return the banner with author initials branding."""
    lines = [BANNER]
    lines.append(f"   {BANNER_SUB}  |  v{__version__}  |  built by {AUTHOR} ({AUTHOR_INITIALS})")
    lines.append("   " + "-" * 62)
    return "\n".join(lines)


__all__ = [
    "__version__",
    "__build__",
    "PRODUCT_NAME",
    "PRODUCT_TAGLINE",
    "AUTHOR",
    "AUTHOR_INITIALS",
    "ORGANIZATION",
    "LICENSE",
    "WEBSITE",
    "BANNER",
    "banner_text",
]
