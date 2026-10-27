"""Machine-readable JSON reporter."""

from __future__ import annotations

import json

from ..version import AUTHOR, AUTHOR_INITIALS, ORGANIZATION, PRODUCT_NAME, __version__
from .base import BaseReporter


class JsonReporter(BaseReporter):
    name = "json"
    extension = "json"

    def render(self) -> str:
        payload = self.report.to_dict()
        payload["generator"] = {
            "product": PRODUCT_NAME,
            "version": __version__,
            "organization": ORGANIZATION,
            "author": AUTHOR,
            "initials": AUTHOR_INITIALS,
        }
        return json.dumps(payload, indent=2, default=str)


__all__ = ["JsonReporter"]
