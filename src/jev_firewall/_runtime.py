"""Event-loop plumbing so one engine serves sync and async frameworks alike.

Jev calls always run on a single background loop owned by the engine. HTTP connection pools
are bound to the loop that created them, and agent frameworks call tools from a mix of
threads, executor pools, and their own loops; pinning the client to one loop avoids
"attached to a different loop" failures and keeps connections warm across calls.
"""

from __future__ import annotations

import asyncio
import contextvars
import threading
from collections.abc import Coroutine
from concurrent.futures import ThreadPoolExecutor
from typing import Any, TypeVar

T = TypeVar("T")


class LoopThread:
    def __init__(self, name: str = "jev-firewall-loop") -> None:
        self._name = name
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def _ensure(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._loop is None or self._loop.is_closed():
                loop = asyncio.new_event_loop()
                ready = threading.Event()

                def run() -> None:
                    asyncio.set_event_loop(loop)
                    loop.call_soon(ready.set)
                    loop.run_forever()

                self._thread = threading.Thread(target=run, name=self._name, daemon=True)
                self._thread.start()
                ready.wait()
                self._loop = loop
            return self._loop

    def run(self, coro: Coroutine[Any, Any, T]) -> T:
        """Run `coro` on the background loop and block the calling thread for the result."""
        return asyncio.run_coroutine_threadsafe(coro, self._ensure()).result()

    async def arun(self, coro: Coroutine[Any, Any, T]) -> T:
        """Run `coro` on the background loop and await it from the caller's loop."""
        return await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(coro, self._ensure()))

    def close(self) -> None:
        with self._lock:
            loop, self._loop = self._loop, None
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(loop.stop)
            if self._thread is not None:
                self._thread.join(timeout=2)
            loop.close()


def run_sync(coro: Coroutine[Any, Any, T]) -> T:
    """Run a coroutine to completion from sync code, in the caller's context.

    Unlike `LoopThread.run`, this preserves the caller's contextvars (LangGraph's `interrupt()`
    depends on them). Works even if the calling thread already has a running loop.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    ctx = contextvars.copy_context()
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(ctx.run, asyncio.run, coro).result()
