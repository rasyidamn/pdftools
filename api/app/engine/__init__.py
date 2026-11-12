from __future__ import annotations

from ..config import Settings
from .base import EngineError, MergeEngine
from .pypdf_engine import PypdfEngine
from .stirling import StirlingEngine

__all__ = ["EngineError", "MergeEngine", "PypdfEngine", "StirlingEngine", "build_engine"]


def build_engine(settings: Settings) -> MergeEngine:
    if settings.engine == "pypdf":
        return PypdfEngine()
    return StirlingEngine(
        settings.stirling_url,
        timeout_s=settings.engine_timeout_s,
        version_label=settings.engine_version_label,
    )