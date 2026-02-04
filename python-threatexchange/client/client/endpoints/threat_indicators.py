"""
Threat Indicators endpoint mixin.

Provides methods for searching threat indicators (indicators of compromise).
"""

from typing import Any, Dict, Iterator, List, Optional, Union

from ..models import IndicatorType, ThreatIndicator


class ThreatIndicatorsMixin:
    """Mixin providing threat indicator operations."""

    def get_threat_indicator(
        self,
        indicator_id: str,
        fields: Optional[List[str]] = None,
    ) -> ThreatIndicator:
        """
        Get a specific threat indicator by ID.

        Args:
            indicator_id: The ID of the threat indicator.
            fields: Optional list of fields to include in the response.

        Returns:
            ThreatIndicator object.

        Raises:
            NotFoundError: If the indicator is not found.
        """
        params: Dict[str, Any] = {}
        if fields:
            params["fields"] = ",".join(fields)

        result = self._get(indicator_id, params)
        return ThreatIndicator.from_dict(result)

    def search_threat_indicators(
        self,
        text: Optional[str] = None,
        type: Optional[Union[IndicatorType, str]] = None,
        since: Optional[int] = None,
        until: Optional[int] = None,
        strict_text: bool = False,
        fields: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ThreatIndicator]:
        """
        Search for threat indicators.

        Args:
            text: Text to search for in indicators.
            type: Type of indicator to filter by.
            since: Unix timestamp to filter indicators after this time.
            until: Unix timestamp to filter indicators before this time.
            strict_text: If True, search for exact text match.
            fields: Optional list of fields to include in the response.
            limit: Maximum number of results to return (None for all).

        Yields:
            ThreatIndicator objects matching the search criteria.
        """
        params: Dict[str, Any] = {}

        if text:
            params["text"] = text
        if type:
            params["type"] = type.value if isinstance(type, IndicatorType) else type
        if since is not None:
            params["since"] = since
        if until is not None:
            params["until"] = until
        if strict_text:
            params["strict_text"] = "true"
        if fields:
            params["fields"] = ",".join(fields)

        yield from self._paginate(
            "threat_indicators",
            params,
            ThreatIndicator.from_dict,
            limit,
        )

    def get_indicator_descriptors(
        self,
        indicator_id: str,
        fields: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> Iterator:
        """
        Get descriptors associated with a threat indicator.

        Args:
            indicator_id: The ID of the threat indicator.
            fields: Optional list of fields to include in the response.
            limit: Maximum number of results to return.

        Yields:
            ThreatDescriptor objects associated with this indicator.
        """
        from ..models import ThreatDescriptor

        params: Dict[str, Any] = {}
        if fields:
            params["fields"] = ",".join(fields)

        yield from self._paginate(
            f"{indicator_id}/descriptors",
            params,
            ThreatDescriptor.from_dict,
            limit,
        )
