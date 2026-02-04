"""
ThreatExchange Members endpoint mixin.

Provides methods for listing ThreatExchange members.
"""

from typing import Any, Dict, Iterator, List, Optional

from ..models import ThreatExchangeMember


class ThreatExchangeMembersMixin:
    """Mixin providing ThreatExchange member operations."""

    def get_threat_exchange_members(
        self,
        fields: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ThreatExchangeMember]:
        """
        Get a list of current ThreatExchange members.

        Args:
            fields: Optional list of fields to include in the response.
            limit: Maximum number of results to return.

        Yields:
            ThreatExchangeMember objects.
        """
        params: Dict[str, Any] = {}
        if fields:
            params["fields"] = ",".join(fields)

        yield from self._paginate(
            "threat_exchange_members",
            params,
            ThreatExchangeMember.from_dict,
            limit,
        )

    def get_member(
        self,
        member_id: str,
        fields: Optional[List[str]] = None,
    ) -> ThreatExchangeMember:
        """
        Get a specific ThreatExchange member by ID.

        Args:
            member_id: The ID of the member (app ID).
            fields: Optional list of fields to include in the response.

        Returns:
            ThreatExchangeMember object.
        """
        params: Dict[str, Any] = {}
        if fields:
            params["fields"] = ",".join(fields)

        result = self._get(member_id, params)
        return ThreatExchangeMember.from_dict(result)
