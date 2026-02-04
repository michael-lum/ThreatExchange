"""
ThreatExchange API Client.

A Python client for interacting with the Facebook ThreatExchange Graph API.
"""

from typing import Any, Dict

from .base import BaseClient
from .endpoints import (
    ThreatDescriptorsMixin,
    ThreatIndicatorsMixin,
    ThreatTagsMixin,
    ThreatUpdatesMixin,
    PrivacyGroupsMixin,
    ThreatExchangeMembersMixin,
)


class ThreatExchangeClient(
    ThreatDescriptorsMixin,
    ThreatIndicatorsMixin,
    ThreatTagsMixin,
    ThreatUpdatesMixin,
    PrivacyGroupsMixin,
    ThreatExchangeMembersMixin,
    BaseClient,
):
    """
    Client for the Facebook ThreatExchange API.

    The ThreatExchange API allows you to share and query threat intelligence
    data with other members of the ThreatExchange community.

    This client provides methods for:
    - Threat Descriptors: Opinions/assessments about indicators
    - Threat Indicators: Indicators of compromise (IOCs)
    - Threat Tags: Labels for grouping threat objects
    - Threat Updates: Incremental sync of threat data
    - Privacy Groups: Sharing controls
    - Members: ThreatExchange participant info

    Example:
        >>> client = ThreatExchangeClient(access_token="your_access_token")
        >>> for descriptor in client.search_threat_descriptors(text="malware"):
        ...     print(descriptor.indicator, descriptor.status)

    To add new endpoints:
        1. Create a new mixin class in threatexchange_client/endpoints/
        2. Add the mixin to this class's inheritance list
        3. The mixin can use self._get, self._post, self._delete, self._paginate
    """

    def get_app_info(self) -> Dict[str, Any]:
        """
        Get information about the current app.

        Returns:
            Dictionary containing app information.
        """
        return self._get("me")

    def whoami(self) -> Dict[str, Any]:
        """
        Get information about the current access token.

        Returns:
            Dictionary containing token information including app_id and user_id.
        """
        return self._get("debug_token", params={"input_token": self.access_token})
