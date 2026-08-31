"""Registrable-domain projection backed only by the lockfile-pinned bundled PSL."""

from __future__ import annotations

import importlib
from functools import lru_cache
from typing import Protocol, cast

from codex_plugin_scanner.guard.runtime.network_policy_contract import Destination, DestinationKind


class _PublicSuffixList(Protocol):
    def privatesuffix(self, domain: str) -> str | None: ...


class _PublicSuffixListFactory(Protocol):
    def __call__(self, *, accept_unknown: bool = ...) -> _PublicSuffixList: ...


@lru_cache(maxsize=1)
def _bundled_psl() -> _PublicSuffixList:
    # The lockfile-pinned dependency embeds its PSL snapshot; never invoke its updater here.
    module = importlib.import_module("publicsuffixlist")
    factory = cast(_PublicSuffixListFactory, module.PublicSuffixList)
    # `accept_unknown=False` disables the PSL algorithm's default wildcard
    # fallback rule, which otherwise treats *any* unrecognized final label as
    # a valid ad-hoc suffix (e.g. `proc.returncode` would otherwise resolve
    # as if `.returncode` were a real TLD). Callers that need a real,
    # registrable-domain signal — not "any dotted string" — depend on this.
    return factory(accept_unknown=False)


def registrable_domain(host: str) -> str | None:
    """Return canonical eTLD+1 using the packaged PSL snapshot, or None for a suffix."""

    canonical = Destination(DestinationKind.HOST, host).value
    result = _bundled_psl().privatesuffix(canonical)
    return str(result) if result is not None else None
