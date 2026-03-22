from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RuntimeProfile(str, Enum):
    passive_only = "passive-only"
    report_only = "report-only"
    lab_safe = "lab-safe"


@dataclass(frozen=True, slots=True)
class ProfileConfig:
    name: RuntimeProfile
    run_passive: bool
    include_approved_active: bool
    report_only: bool


PROFILE_DEFAULTS: dict[RuntimeProfile, ProfileConfig] = {
    RuntimeProfile.passive_only: ProfileConfig(
        name=RuntimeProfile.passive_only,
        run_passive=True,
        include_approved_active=False,
        report_only=False,
    ),
    RuntimeProfile.report_only: ProfileConfig(
        name=RuntimeProfile.report_only,
        run_passive=False,
        include_approved_active=False,
        report_only=True,
    ),
    RuntimeProfile.lab_safe: ProfileConfig(
        name=RuntimeProfile.lab_safe,
        run_passive=True,
        include_approved_active=True,
        report_only=False,
    ),
}


def resolve_profile(profile: str | RuntimeProfile | None) -> ProfileConfig:
    if profile is None:
        return PROFILE_DEFAULTS[RuntimeProfile.passive_only]

    if isinstance(profile, RuntimeProfile):
        return PROFILE_DEFAULTS[profile]

    normalized = profile.strip().replace("_", "-")
    for candidate in RuntimeProfile:
        if candidate.value == normalized:
            return PROFILE_DEFAULTS[candidate]

    options = ", ".join(sorted(p.value for p in RuntimeProfile))
    raise ValueError(f"Unknown profile '{profile}'. Expected one of: {options}.")

