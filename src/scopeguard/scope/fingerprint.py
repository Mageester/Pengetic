from __future__ import annotations

import hashlib
import json

from .models import ScopePackage


def scope_fingerprint(scope: ScopePackage) -> str:
    payload = json.dumps(scope.canonical_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

