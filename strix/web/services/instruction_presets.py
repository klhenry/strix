"""Short-lived, exact-request credential handoff for legacy app callers."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit
from uuid import uuid4


if TYPE_CHECKING:
    from strix.web.models.api_v1 import InstructionPresetRequest, ScanRequest


def _origin(value: str) -> tuple[str, str | None, int]:
    parsed = urlsplit(value)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


@dataclass
class _Preset:
    target: str
    callback_origin: tuple[str, str | None, int]
    scan_type: str
    instruction: str = field(repr=False)
    expires_at: float


class InstructionPresets:
    """Parent-process-only registry; never logged, listed, or persisted."""

    def __init__(self) -> None:
        self._items: dict[str, _Preset] = {}

    def _expire(self) -> None:
        now = time.monotonic()
        self._items = {key: item for key, item in self._items.items() if item.expires_at > now}

    def register(self, request: InstructionPresetRequest) -> str:
        self._expire()
        if len(self._items) >= 20:
            raise RuntimeError("Instruction preset capacity reached")
        target = str(request.target_url)
        origin = _origin(str(request.callback_origin))
        if any(
            item.target == target
            and item.callback_origin == origin
            and item.scan_type == request.scan_type
            for item in self._items.values()
        ):
            raise RuntimeError("An unconsumed preset already matches this exact request")
        identifier = str(uuid4())
        self._items[identifier] = _Preset(
            target,
            origin,
            request.scan_type,
            request.instruction,
            time.monotonic() + request.expires_in_seconds,
        )
        return identifier

    def consume(self, request: ScanRequest) -> str:
        self._expire()
        for key, item in self._items.items():
            if (
                request.resolved_targets() == [item.target]
                and _origin(str(request.callback_url)) == item.callback_origin
                and request.scan_type == item.scan_type
            ):
                del self._items[key]
                return item.instruction
        return ""

    def revoke(self, identifier: str) -> None:
        self._items.pop(identifier, None)
