"""
Data models for ThreatExchange API responses.

This module contains dataclasses representing the various objects
returned by the ThreatExchange API.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union


# =============================================================================
# Enums
# =============================================================================


class IndicatorType(str, Enum):
    """Types of threat indicators."""

    ADJUST_TOKEN = "ADJUST_TOKEN"
    API_KEY = "API_KEY"
    AS_NUMBER = "AS_NUMBER"
    BANNER = "BANNER"
    CMD_LINE = "CMD_LINE"
    COOKIE_NAME = "COOKIE_NAME"
    CRX = "CRX"
    DEBUG_STRING = "DEBUG_STRING"
    DEST_PORT = "DEST_PORT"
    DIRECTORY = "DIRECTORY"
    DOMAIN = "DOMAIN"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    FILE_CREATED = "FILE_CREATED"
    FILE_DELETED = "FILE_DELETED"
    FILE_MOVED = "FILE_MOVED"
    FILE_NAME = "FILE_NAME"
    FILE_OPENED = "FILE_OPENED"
    FILE_READ = "FILE_READ"
    FILE_WRITTEN = "FILE_WRITTEN"
    HASH_IMPHASH = "HASH_IMPHASH"
    HASH_MD5 = "HASH_MD5"
    HASH_PDQ = "HASH_PDQ"
    HASH_SHA1 = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    HASH_SHA3_256 = "HASH_SHA3_256"
    HASH_SSDEEP = "HASH_SSDEEP"
    HASH_TMK = "HASH_TMK"
    HTML_ID = "HTML_ID"
    HTTP_REQUEST = "HTTP_REQUEST"
    IP_ADDRESS = "IP_ADDRESS"
    IP_SUBNET = "IP_SUBNET"
    ISP = "ISP"
    LATITUDE = "LATITUDE"
    LAUNCH_AGENT = "LAUNCH_AGENT"
    LOCATION = "LOCATION"
    LONGITUDE = "LONGITUDE"
    MALWARE_NAME = "MALWARE_NAME"
    MEMORY_ALLOC = "MEMORY_ALLOC"
    MEMORY_PROTECT = "MEMORY_PROTECT"
    MEMORY_WRITTEN = "MEMORY_WRITTEN"
    MUTANT_CREATED = "MUTANT_CREATED"
    MUTEX = "MUTEX"
    NAME_SERVER = "NAME_SERVER"
    OTHER_FILE_OP = "OTHER_FILE_OP"
    PASSWORD = "PASSWORD"
    PASSWORD_SALT = "PASSWORD_SALT"
    PAYLOAD_DATA = "PAYLOAD_DATA"
    PAYLOAD_TYPE = "PAYLOAD_TYPE"
    POST_DATA = "POST_DATA"
    PROTOCOL = "PROTOCOL"
    REFERER = "REFERER"
    REGISTRAR = "REGISTRAR"
    REGISTRY_KEY = "REGISTRY_KEY"
    REG_KEY_CREATED = "REG_KEY_CREATED"
    REG_KEY_DELETED = "REG_KEY_DELETED"
    REG_KEY_ENUMERATED = "REG_KEY_ENUMERATED"
    REG_KEY_MONITORED = "REG_KEY_MONITORED"
    REG_KEY_OPENED = "REG_KEY_OPENED"
    REG_KEY_VALUE_CREATED = "REG_KEY_VALUE_CREATED"
    REG_KEY_VALUE_DELETED = "REG_KEY_VALUE_DELETED"
    REG_KEY_VALUE_MODIFIED = "REG_KEY_VALUE_MODIFIED"
    REG_KEY_VALUE_QUERIED = "REG_KEY_VALUE_QUERIED"
    SIGNATURE = "SIGNATURE"
    SOURCE_PORT = "SOURCE_PORT"
    TELEPHONE = "TELEPHONE"
    TEXT_STRING = "TEXT_STRING"
    TREND_QUERY = "TREND_QUERY"
    URI = "URI"
    USER_AGENT = "USER_AGENT"
    VOLUME_QUERIED = "VOLUME_QUERIED"
    WEBSTORAGE_KEY = "WEBSTORAGE_KEY"
    WEB_PAYLOAD = "WEB_PAYLOAD"
    WHOIS_NAME = "WHOIS_NAME"
    WHOIS_ADDR1 = "WHOIS_ADDR1"
    WHOIS_ADDR2 = "WHOIS_ADDR2"
    XPI = "XPI"


# Alias for backwards compatibility
DescriptorType = IndicatorType


class Status(str, Enum):
    """Status of a threat (maliciousness)."""

    MALICIOUS = "MALICIOUS"
    NON_MALICIOUS = "NON_MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    """Severity level of a threat (from least to most severe)."""

    INFO = "INFO"
    WARNING = "WARNING"
    SEVERE = "SEVERE"


class ShareLevel(str, Enum):
    """
    Traffic Light Protocol (TLP) sharing levels.

    Defines how data may be re-shared within and outside ThreatExchange.
    """

    WHITE = "WHITE"  # Unlimited sharing
    GREEN = "GREEN"  # Community sharing
    AMBER = "AMBER"  # Limited sharing
    RED = "RED"  # Most restricted


class ReviewStatus(str, Enum):
    """Review status for threat descriptors."""

    REVIEWED_AUTOMATICALLY = "REVIEWED_AUTOMATICALLY"
    REVIEWED_MANUALLY = "REVIEWED_MANUALLY"
    UNREVIEWED = "UNREVIEWED"


class PrivacyType(str, Enum):
    """Privacy type for threat data."""

    VISIBLE = "VISIBLE"
    HAS_PRIVACY_GROUP = "HAS_PRIVACY_GROUP"
    HAS_WHITELIST = "HAS_WHITELIST"


class PrecisionType(str, Enum):
    """Precision of threat intelligence detection."""

    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# =============================================================================
# Helper Functions
# =============================================================================


def _parse_datetime(value: Optional[Union[str, int]]) -> Optional[datetime]:
    """Parse a datetime value from the API."""
    if value is None:
        return None
    if isinstance(value, int):
        return datetime.fromtimestamp(value)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _parse_enum(enum_cls, value):
    """Parse an enum value, returning the raw value if not recognized."""
    if value is None:
        return None
    try:
        return enum_cls(value)
    except ValueError:
        return value


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class ThreatTag:
    """
    Represents a tag applied to threat data.

    Tags are labels used to group threat objects together.
    """

    id: str
    text: str
    tagged_objects_count: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatTag":
        return cls(
            id=data.get("id", ""),
            text=data.get("text", ""),
            tagged_objects_count=data.get("tagged_objects_count", 0),
        )


@dataclass
class ThreatPrivacyGroup:
    """
    Represents a privacy group for sharing threat data.

    A mutable list of members to share data with. Can be promoted
    to a "Program" which provides additional API and UI features.
    """

    id: str
    name: str
    description: str = ""
    members_can_see: bool = True
    members_can_use: bool = True
    member_count: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatPrivacyGroup":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            members_can_see=data.get("members_can_see", True),
            members_can_use=data.get("members_can_use", True),
            member_count=data.get("member_count", 0),
        )


@dataclass
class ThreatExchangeMember:
    """
    Represents a participant within ThreatExchange.

    Members are typically Facebook apps that have been granted
    access to ThreatExchange.
    """

    id: str
    name: str
    email: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatExchangeMember":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            email=data.get("email"),
        )


@dataclass
class ThreatIndicator:
    """
    Represents an indicator of compromise (IOC).

    This is the actual threat data - a domain, IP, hash, etc.
    """

    id: str
    indicator: Optional[str] = None
    type: Optional[Union[IndicatorType, str]] = None
    added_on: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatIndicator":
        return cls(
            id=data.get("id", ""),
            indicator=data.get("indicator"),
            type=_parse_enum(IndicatorType, data.get("type")),
            added_on=_parse_datetime(data.get("added_on")),
            last_updated=_parse_datetime(data.get("last_updated")),
            raw_data=data,
        )


@dataclass
class ThreatDescriptor:
    """
    Represents subjective context provided by a ThreatExchangeMember
    for a ThreatIndicator.

    This is an opinion/assessment about an indicator, including status,
    severity, description, and other metadata.
    """

    id: str
    indicator: Optional[str] = None
    type: Optional[Union[IndicatorType, str]] = None
    status: Optional[Union[Status, str]] = None
    severity: Optional[Union[Severity, str]] = None
    share_level: Optional[Union[ShareLevel, str]] = None
    description: Optional[str] = None
    owner_id: Optional[str] = None
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    privacy_type: Optional[Union[PrivacyType, str]] = None
    review_status: Optional[Union[ReviewStatus, str]] = None
    precision: Optional[Union[PrecisionType, str]] = None
    added_on: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    expired_on: Optional[datetime] = None
    first_active: Optional[datetime] = None
    last_active: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    reactions: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatDescriptor":
        owner = data.get("owner", {})
        tags_data = data.get("tags", {}).get("data", [])

        # Handle indicator - can be nested or a raw string
        indicator_data = data.get("indicator", {})
        if isinstance(indicator_data, dict):
            indicator = indicator_data.get("indicator")
        else:
            indicator = indicator_data or data.get("raw_indicator")

        return cls(
            id=data.get("id", ""),
            indicator=indicator,
            type=_parse_enum(IndicatorType, data.get("type")),
            status=_parse_enum(Status, data.get("status")),
            severity=_parse_enum(Severity, data.get("severity")),
            share_level=_parse_enum(ShareLevel, data.get("share_level")),
            description=data.get("description"),
            owner_id=owner.get("id"),
            owner_name=owner.get("name"),
            owner_email=owner.get("email"),
            privacy_type=_parse_enum(PrivacyType, data.get("privacy_type")),
            review_status=_parse_enum(ReviewStatus, data.get("review_status")),
            precision=_parse_enum(PrecisionType, data.get("precision")),
            added_on=_parse_datetime(data.get("added_on")),
            last_updated=_parse_datetime(data.get("last_updated")),
            expired_on=_parse_datetime(data.get("expired_on")),
            first_active=_parse_datetime(data.get("first_active")),
            last_active=_parse_datetime(data.get("last_active")),
            tags=[tag.get("text", "") for tag in tags_data],
            reactions=data.get("reactions", {}),
            raw_data=data,
        )


@dataclass
class ThreatUpdate:
    """
    Represents an update to threat data.

    Used for incremental sync via the threat_updates endpoint.
    """

    id: str
    type: Optional[str] = None
    time: Optional[datetime] = None
    should_delete: bool = False
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatUpdate":
        return cls(
            id=data.get("id", ""),
            type=data.get("type"),
            time=_parse_datetime(data.get("time")),
            should_delete=data.get("should_delete", False),
            raw_data=data,
        )


@dataclass
class PaginatedResponse:
    """Wrapper for paginated API responses."""

    data: List[Any]
    next_url: Optional[str] = None
    has_next: bool = False

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
        item_factory: Optional[Callable] = None,
    ) -> "PaginatedResponse":
        items = data.get("data", [])
        if item_factory:
            items = [item_factory(item) for item in items]

        paging = data.get("paging", {})
        next_url = paging.get("next")

        return cls(
            data=items,
            next_url=next_url,
            has_next=next_url is not None,
        )
