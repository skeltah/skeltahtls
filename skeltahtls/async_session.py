"""asyncio wrapper around Session.

The Go library is blocking, so every request runs in a thread pool; the ctypes call
releases the GIL, so many sessions can run concurrently. All Session attributes
(headers, cookies, header_order, force_http1, ...) work exactly the same.
"""
from __future__ import annotations

import asyncio
import functools
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from .response import Response
from .session import Session


class AsyncSession(Session):
    # shared pool so thousands of sessions do not each spawn threads
    _executor: Optional[ThreadPoolExecutor] = None
    _executor_workers = 64

    @classmethod
    def configure_executor(cls, max_workers: int) -> None:
        """Set the size of the shared thread pool (call before the first request)."""
        cls._executor_workers = max_workers
        cls._executor = None

    @classmethod
    def _pool(cls) -> ThreadPoolExecutor:
        if cls._executor is None:
            cls._executor = ThreadPoolExecutor(max_workers=cls._executor_workers, thread_name_prefix="skeltahtls")
        return cls._executor

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._pool(), super().close)

    async def execute_request(self, method: str, url: str, **kwargs: Any) -> Response:  # type: ignore[override]
        loop = asyncio.get_running_loop()
        call = functools.partial(Session.execute_request, self, method, url, **kwargs)
        return await loop.run_in_executor(self._pool(), call)

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:  # type: ignore[override]
        return await self.execute_request(method, url, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> Response:  # type: ignore[override]
        return await self.execute_request("GET", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> Response:  # type: ignore[override]
        return await self.execute_request("OPTIONS", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Response:  # type: ignore[override]
        kwargs.setdefault("allow_redirects", False)
        return await self.execute_request("HEAD", url, **kwargs)

    async def post(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:  # type: ignore[override]
        return await self.execute_request("POST", url, data=data, json=json, **kwargs)

    async def put(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:  # type: ignore[override]
        return await self.execute_request("PUT", url, data=data, json=json, **kwargs)

    async def patch(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:  # type: ignore[override]
        return await self.execute_request("PATCH", url, data=data, json=json, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> Response:  # type: ignore[override]
        return await self.execute_request("DELETE", url, **kwargs)
