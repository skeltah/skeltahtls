"""Compatibility shim: ``from skeltahtls.async_client import AsyncSession`` (tls_client2 layout)."""
from ..async_session import AsyncSession

__all__ = ["AsyncSession"]
