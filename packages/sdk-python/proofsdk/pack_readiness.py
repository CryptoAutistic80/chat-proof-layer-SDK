from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def select_pack_readiness(pack: Mapping[str, Any]) -> dict[str, Any] | None:
    if pack.get("pack_completeness_profile") or pack.get("pack_completeness_status"):
        return {
            "source": "pack_scoped",
            "profile": pack.get("pack_completeness_profile"),
            "status": pack.get("pack_completeness_status"),
            "pass_count": pack.get("pack_completeness_pass_count"),
            "warn_count": pack.get("pack_completeness_warn_count"),
            "fail_count": pack.get("pack_completeness_fail_count"),
        }

    if pack.get("completeness_profile") or pack.get("completeness_status"):
        return {
            "source": "bundle_aggregate",
            "profile": pack.get("completeness_profile"),
            "status": pack.get("completeness_status"),
            "pass_count": pack.get("completeness_pass_count"),
            "warn_count": pack.get("completeness_warn_count"),
            "fail_count": pack.get("completeness_fail_count"),
        }

    return None
