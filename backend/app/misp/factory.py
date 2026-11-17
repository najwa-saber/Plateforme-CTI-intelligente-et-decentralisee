"""Selection of the MISP adapter according to MISP_MODE.

* ``real``      : PyMISP only. Failures are reported (503), never hidden.
* ``simulated`` : simulated adapter only (explicit development choice).
* ``auto``      : real MISP when reachable, otherwise simulated adapter with the
                  reason recorded and displayed. The probe is repeated every 60 s.
"""
from __future__ import annotations

import logging
import threading
import time

from app.core.config import get_settings
from app.core.errors import MispError
from app.misp.base import MispAdapter
from app.misp.pymisp_adapter import PyMispAdapter
from app.misp.simulated import SimulatedMispAdapter

logger = logging.getLogger("cti.misp")
_lock = threading.Lock()
_cache: dict = {"adapter": None, "checked_at": 0.0}
PROBE_INTERVAL_S = 60.0


def reset_misp_adapter() -> None:
    with _lock:
        _cache.update(adapter=None, checked_at=0.0)


def get_misp_adapter() -> MispAdapter:
    settings = get_settings()
    with _lock:
        cached = _cache["adapter"]
        if cached is not None and (settings.misp_mode != "auto" or cached.mode == "real"
                                   or time.monotonic() - _cache["checked_at"] < PROBE_INTERVAL_S):
            return cached
        if settings.misp_mode == "simulated":
            adapter: MispAdapter = SimulatedMispAdapter(reason="MISP_MODE=simulated")
        elif settings.misp_mode == "real":
            adapter = PyMispAdapter(settings)
        else:
            try:
                real = PyMispAdapter(settings)
                real.health()
                adapter = real
                logger.info("MISP auto mode: real instance reachable at %s", settings.misp_url)
            except MispError as exc:
                logger.warning("MISP auto mode: real instance unavailable (%s) -> simulated adapter", exc.message)
                adapter = SimulatedMispAdapter(reason=f"auto fallback: {exc.message}")
        _cache.update(adapter=adapter, checked_at=time.monotonic())
        return adapter
