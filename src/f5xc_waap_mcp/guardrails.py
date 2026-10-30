"""Usage guardrails: per-identity and global rate limits, session call cap and
loop detection. All state is in memory and bounded (LRU eviction), so a client
rotating identities or sessions cannot grow it without limit."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from .config import Settings
from .errors import Code, SecureError

WINDOW_S = 60.0
MAX_TRACKED = 4096


@dataclass
class _Session:
    total: int = 0
    last_call: tuple[str, str] | None = None
    repeats: int = 0


@dataclass
class _Bounded:
    items: OrderedDict = field(default_factory=OrderedDict)

    def get(self, key: str, factory):
        if key in self.items:
            self.items.move_to_end(key)
            return self.items[key]
        value = factory()
        self.items[key] = value
        while len(self.items) > MAX_TRACKED:
            self.items.popitem(last=False)
        return value


class Guardrails:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._users = _Bounded()
        self._sessions = _Bounded()
        self._global: deque[float] = deque()
        self._lock = threading.Lock()

    @staticmethod
    def _trim(calls: deque[float], now: float) -> None:
        while calls and now - calls[0] > WINDOW_S:
            calls.popleft()

    def check(self, *, identity: str, session: str, tool: str, args_hash: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        s = self._settings
        with self._lock:
            sess: _Session = self._sessions.get(session, _Session)
            if sess.total >= s.session_call_cap:
                raise SecureError(Code.SESSION_CAP_REACHED)

            user: deque[float] = self._users.get(identity, deque)
            self._trim(user, now)
            self._trim(self._global, now)
            if len(user) >= s.rate_per_minute or len(self._global) >= s.global_rate_per_minute:
                raise SecureError(Code.RATE_LIMITED)

            call = (tool, args_hash)
            repeats = sess.repeats + 1 if sess.last_call == call else 1
            if repeats >= s.loop_threshold:
                raise SecureError(Code.LOOP_DETECTED)

            sess.last_call, sess.repeats = call, repeats
            sess.total += 1
            user.append(now)
            self._global.append(now)
