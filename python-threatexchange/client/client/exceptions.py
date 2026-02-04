"""
Custom exceptions for the ThreatExchange client.
"""

from typing import Dict, Optional


class ThreatExchangeError(Exception):
    """Base exception for ThreatExchange API errors."""

    def __init__(
        self,
        message: str,
        code: Optional[int] = None,
        details: Optional[Dict] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}

    def __str__(self) -> str:
        if self.code:
            return f"[{self.code}] {self.message}"
        return self.message


class AuthenticationError(ThreatExchangeError):
    """Raised when authentication fails (invalid or expired access token)."""

    pass


class RateLimitError(ThreatExchangeError):
    """Raised when API rate limits are exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        **kwargs,
    ):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class NotFoundError(ThreatExchangeError):
    """Raised when a requested resource is not found."""

    pass


class ValidationError(ThreatExchangeError):
    """Raised when request parameters fail validation."""

    pass


class PermissionError(ThreatExchangeError):
    """Raised when the user lacks permission to access a resource."""

    pass
