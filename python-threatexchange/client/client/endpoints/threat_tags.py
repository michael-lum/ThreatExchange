"""
Threat Tags endpoint mixin.

Provides methods for searching tags and getting tagged objects.
"""

from typing import Iterator, Optional

from ..models import ThreatDescriptor, ThreatTag


class ThreatTagsMixin:
    """Mixin providing threat tag operations."""

    def get_threat_tag(self, tag_id: str) -> ThreatTag:
        """
        Get a specific threat tag by ID.

        Args:
            tag_id: The ID of the threat tag.

        Returns:
            ThreatTag object.
        """
        result = self._get(tag_id)
        return ThreatTag.from_dict(result)

    def search_threat_tags(
        self,
        text: str,
        limit: Optional[int] = None,
    ) -> Iterator[ThreatTag]:
        """
        Search for threat tags.

        Args:
            text: Text to search for in tag names.
            limit: Maximum number of results to return.

        Yields:
            ThreatTag objects matching the search criteria.
        """
        params = {"text": text}

        yield from self._paginate(
            "threat_tags",
            params,
            ThreatTag.from_dict,
            limit,
        )

    def get_tagged_objects(
        self,
        tag_id: str,
        limit: Optional[int] = None,
    ) -> Iterator[ThreatDescriptor]:
        """
        Get objects tagged with a specific tag.

        Args:
            tag_id: The ID of the threat tag.
            limit: Maximum number of results to return.

        Yields:
            ThreatDescriptor objects with this tag.
        """
        yield from self._paginate(
            f"{tag_id}/tagged_objects",
            None,
            ThreatDescriptor.from_dict,
            limit,
        )
