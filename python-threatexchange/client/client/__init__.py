"""
ThreatExchange Python Client

A Python client library for interacting with the Facebook ThreatExchange API.
"""

from .client import ThreatExchangeClient
from .models import (
    # Data models
    ThreatDescriptor,
    ThreatIndicator,
    ThreatTag,
    ThreatPrivacyGroup,
    ThreatExchangeMember,
    ThreatUpdate,
    # Enums
    IndicatorType,
    DescriptorType,  # Alias for IndicatorType
    Status,
    Severity,
    ShareLevel,
    ReviewStatus,
    PrivacyType,
    PrecisionType,
)
from .exceptions import (
    ThreatExchangeError,
    AuthenticationError,
    RateLimitError,
    NotFoundError,
    ValidationError,
)

__version__ = "1.0.0"
__all__ = [
    # Client
    "ThreatExchangeClient",
    # Models
    "ThreatDescriptor",
    "ThreatIndicator",
    "ThreatTag",
    "ThreatPrivacyGroup",
    "ThreatExchangeMember",
    "ThreatUpdate",
    # Enums
    "IndicatorType",
    "DescriptorType",
    "Status",
    "Severity",
    "ShareLevel",
    "ReviewStatus",
    "PrivacyType",
    "PrecisionType",
    # Exceptions
    "ThreatExchangeError",
    "AuthenticationError",
    "RateLimitError",
    "NotFoundError",
    "ValidationError",
]
