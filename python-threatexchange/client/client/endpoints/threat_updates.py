"""
Threat Updates endpoint mixin.

Provides methods for getting incremental updates to threat data.
"""

from typing import Any, Dict, Iterator, List, Optional

from ..models import ThreatUpdate


class ThreatUpdatesMixin:
    """Mixin providing threat update operations."""

    def get_threat_updates(
        self,
        privacy_group_id: str,
        since: Optional[int] = None,
        until: Optional[int] = None,
        types: Optional[List[str]] = None,
        fields: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ThreatUpdate]:
        """
        Get updates to threat data for a privacy group.

        This endpoint allows you to efficiently sync changes to threat data
        by fetching only the updates since your last sync.

        Args:
            privacy_group_id: The ID of the privacy group to get updates for.
            since: Unix timestamp to get updates after.
            until: Unix timestamp to get updates before.
            types: List of types to filter by (e.g., ["THREAT_DESCRIPTOR"]).
            fields: Optional list of fields to include.
            limit: Maximum number of results to return.

        Yields:
            ThreatUpdate objects representing changes to threat data.
        """
        params: Dict[str, Any] = {}

        if since is not None:
            params["since"] = since
        if until is not None:
            params["until"] = until
        if types:
            params["types"] = ",".join(types)
        if fields:
            params["fields"] = ",".join(fields)

        yield from self._paginate(
            f"{privacy_group_id}/threat_updates",
            params,
            ThreatUpdate.from_dict,
            limit,
        )
