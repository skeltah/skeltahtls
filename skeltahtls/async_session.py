"""asyncio wrapper around Session.

The Go library is blocking, so every request runs in a thread pool; the ctypes call
releases the GIL, so many sessions can run concurrently. All Session attributes
(headers, cookies, header_order, force_http1, ...) work exactly the same.
"""
from __future__ import annotations

import asyncio
import functools
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Mapping, Optional, Sequence

from .response import Response
from .cookiejar import CookieInput
from .session import _UNSET, ProxyInput, Session


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

    async def request(
        self,
        method: str,
        url: str,
        *,
        data: Any = None,
        json: Any = None,
        files: FilesInput = None,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        cookies: CookieInput = None,
        allow_redirects: bool = True,
        verify: Optional[bool] = None,
        timeout: Optional[float] = _UNSET,
        proxy: ProxyInput = None,
        proxies: ProxyInput = None,
        header_order: Optional[Sequence[str]] = None,
        host_override: Optional[str] = None,
    ) -> Response:  # type: ignore[override]
        """Send a request with an arbitrary method.

        See ``Session.execute_request`` for what every parameter does.
        """
        return await self.execute_request(
            method,
            url,
            data=data,
            json=json,
            files=files,
            params=params,
            headers=headers,
            cookies=cookies,
            allow_redirects=allow_redirects,
            verify=verify,
            timeout=timeout,
            proxy=proxy,
            proxies=proxies,
            header_order=header_order,
            host_override=host_override,
        )

    async def get(
        self,
        url: str,
        *,
        data: Any = None,
        json: Any = None,
        files: FilesInput = None,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        cookies: CookieInput = None,
        allow_redirects: bool = True,
        verify: Optional[bool] = None,
        timeout: Optional[float] = _UNSET,
        proxy: ProxyInput = None,
        proxies: ProxyInput = None,
        header_order: Optional[Sequence[str]] = None,
        host_override: Optional[str] = None,
    ) -> Response:  # type: ignore[override]
        """Send a GET request.

        See ``Session.execute_request`` for what every parameter does.
        """
        return await self.execute_request(
            "GET",
            url,
            data=data,
            json=json,
            files=files,
            params=params,
            headers=headers,
            cookies=cookies,
            allow_redirects=allow_redirects,
            verify=verify,
            timeout=timeout,
            proxy=proxy,
            proxies=proxies,
            header_order=header_order,
            host_override=host_override,
        )

    async def options(
        self,
        url: str,
        *,
        data: Any = None,
        json: Any = None,
        files: FilesInput = None,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        cookies: CookieInput = None,
        allow_redirects: bool = True,
        verify: Optional[bool] = None,
        timeout: Optional[float] = _UNSET,
        proxy: ProxyInput = None,
        proxies: ProxyInput = None,
        header_order: Optional[Sequence[str]] = None,
        host_override: Optional[str] = None,
    ) -> Response:  # type: ignore[override]
        """Send an OPTIONS request.

        See ``Session.execute_request`` for what every parameter does.
        """
        return await self.execute_request(
            "OPTIONS",
            url,
            data=data,
            json=json,
            files=files,
            params=params,
            headers=headers,
            cookies=cookies,
            allow_redirects=allow_redirects,
            verify=verify,
            timeout=timeout,
            proxy=proxy,
            proxies=proxies,
            header_order=header_order,
            host_override=host_override,
        )

    async def head(
        self,
        url: str,
        *,
        data: Any = None,
        json: Any = None,
        files: FilesInput = None,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        cookies: CookieInput = None,
        allow_redirects: bool = False,
        verify: Optional[bool] = None,
        timeout: Optional[float] = _UNSET,
        proxy: ProxyInput = None,
        proxies: ProxyInput = None,
        header_order: Optional[Sequence[str]] = None,
        host_override: Optional[str] = None,
    ) -> Response:  # type: ignore[override]
        """Send a HEAD request (redirects are not followed by default).

        See ``Session.execute_request`` for what every parameter does.
        """
        return await self.execute_request(
            "HEAD",
            url,
            data=data,
            json=json,
            files=files,
            params=params,
            headers=headers,
            cookies=cookies,
            allow_redirects=allow_redirects,
            verify=verify,
            timeout=timeout,
            proxy=proxy,
            proxies=proxies,
            header_order=header_order,
            host_override=host_override,
        )

    async def post(
        self,
        url: str,
        data: Any = None,
        json: Any = None,
        *,
        files: FilesInput = None,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        cookies: CookieInput = None,
        allow_redirects: bool = True,
        verify: Optional[bool] = None,
        timeout: Optional[float] = _UNSET,
        proxy: ProxyInput = None,
        proxies: ProxyInput = None,
        header_order: Optional[Sequence[str]] = None,
        host_override: Optional[str] = None,
    ) -> Response:  # type: ignore[override]
        """Send a POST request.

        See ``Session.execute_request`` for what every parameter does.
        """
        return await self.execute_request(
            "POST",
            url,
            data=data,
            json=json,
            files=files,
            params=params,
            headers=headers,
            cookies=cookies,
            allow_redirects=allow_redirects,
            verify=verify,
            timeout=timeout,
            proxy=proxy,
            proxies=proxies,
            header_order=header_order,
            host_override=host_override,
        )

    async def put(
        self,
        url: str,
        data: Any = None,
        json: Any = None,
        *,
        files: FilesInput = None,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        cookies: CookieInput = None,
        allow_redirects: bool = True,
        verify: Optional[bool] = None,
        timeout: Optional[float] = _UNSET,
        proxy: ProxyInput = None,
        proxies: ProxyInput = None,
        header_order: Optional[Sequence[str]] = None,
        host_override: Optional[str] = None,
    ) -> Response:  # type: ignore[override]
        """Send a PUT request.

        See ``Session.execute_request`` for what every parameter does.
        """
        return await self.execute_request(
            "PUT",
            url,
            data=data,
            json=json,
            files=files,
            params=params,
            headers=headers,
            cookies=cookies,
            allow_redirects=allow_redirects,
            verify=verify,
            timeout=timeout,
            proxy=proxy,
            proxies=proxies,
            header_order=header_order,
            host_override=host_override,
        )

    async def patch(
        self,
        url: str,
        data: Any = None,
        json: Any = None,
        *,
        files: FilesInput = None,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        cookies: CookieInput = None,
        allow_redirects: bool = True,
        verify: Optional[bool] = None,
        timeout: Optional[float] = _UNSET,
        proxy: ProxyInput = None,
        proxies: ProxyInput = None,
        header_order: Optional[Sequence[str]] = None,
        host_override: Optional[str] = None,
    ) -> Response:  # type: ignore[override]
        """Send a PATCH request.

        See ``Session.execute_request`` for what every parameter does.
        """
        return await self.execute_request(
            "PATCH",
            url,
            data=data,
            json=json,
            files=files,
            params=params,
            headers=headers,
            cookies=cookies,
            allow_redirects=allow_redirects,
            verify=verify,
            timeout=timeout,
            proxy=proxy,
            proxies=proxies,
            header_order=header_order,
            host_override=host_override,
        )

    async def delete(
        self,
        url: str,
        *,
        data: Any = None,
        json: Any = None,
        files: FilesInput = None,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        cookies: CookieInput = None,
        allow_redirects: bool = True,
        verify: Optional[bool] = None,
        timeout: Optional[float] = _UNSET,
        proxy: ProxyInput = None,
        proxies: ProxyInput = None,
        header_order: Optional[Sequence[str]] = None,
        host_override: Optional[str] = None,
    ) -> Response:  # type: ignore[override]
        """Send a DELETE request.

        See ``Session.execute_request`` for what every parameter does.
        """
        return await self.execute_request(
            "DELETE",
            url,
            data=data,
            json=json,
            files=files,
            params=params,
            headers=headers,
            cookies=cookies,
            allow_redirects=allow_redirects,
            verify=verify,
            timeout=timeout,
            proxy=proxy,
            proxies=proxies,
            header_order=header_order,
            host_override=host_override,
        )
