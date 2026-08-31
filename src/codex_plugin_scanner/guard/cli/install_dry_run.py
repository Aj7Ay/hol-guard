"""Dry-run helpers for Guard harness install flows."""

from __future__ import annotations

from ..adapters.base import HarnessContext
from ..store import GuardStore
from .install_commands import _resolve_targets, build_harness_setup_plan


def build_managed_install_plan(
    requested_harness: str | None,
    install_all: bool,
    context: HarnessContext,
    store: GuardStore,
) -> dict[str, object]:
    targets = _resolve_targets("install", requested_harness, install_all, context, store)
    plans = [build_harness_setup_plan("connect", harness, context, dry_run=True) for harness in targets]
    # `setup_plans` is the single source of truth. It used to also be aliased
    # whole to `setup_plan` and flattened key-by-key onto the top level when
    # there was exactly one target, which put `setup_steps`/`verify_steps`/
    # `repair_steps`/`coverage` in the output three times over.
    return {
        "dry_run": True,
        "setup_plans": plans,
        "auto_detected": requested_harness is None or install_all,
    }


__all__ = ["build_managed_install_plan"]
