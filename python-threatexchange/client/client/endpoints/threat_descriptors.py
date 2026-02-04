"""
Threat Descriptors endpoint mixin.

Provides methods for creating, reading, updating, and deleting threat descriptors.
"""

from typing import Any, Dict, Iterator, List, Optional, Union

from ..models import (
    DescriptorType,
    ReviewStatus,
    Severity,
    ShareLevel,
    Status,
    ThreatDescriptor,
)


class ThreatDescriptorsMixin:
    """Mixin providing threat descriptor operations."""

    def get_threat_descriptor(
        self,
        descriptor_id: str,
        fields: Optional[List[str]] = None,
    ) -> ThreatDescriptor:
        """
        Get a specific threat descriptor by ID.

        Args:
            descriptor_id: The ID of the threat descriptor.
            fields: Optional list of fields to include in the response.

        Returns:
            ThreatDescriptor object.

        Raises:
            NotFoundError: If the descriptor is not found.
        """
        params: Dict[str, Any] = {}
        if fields:
            params["fields"] = ",".join(fields)

        result = self._get(descriptor_id, params)
        return ThreatDescriptor.from_dict(result)

    def search_threat_descriptors(
        self,
        text: Optional[str] = None,
        type: Optional[Union[DescriptorType, str]] = None,
        status: Optional[Union[Status, str]] = None,
        share_level: Optional[Union[ShareLevel, str]] = None,
        owner: Optional[str] = None,
        tags: Optional[List[str]] = None,
        since: Optional[int] = None,
        until: Optional[int] = None,
        strict_text: bool = False,
        fields: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> Iterator[ThreatDescriptor]:
        """
        Search for threat descriptors.

        Args:
            text: Text to search for in indicators.
            type: Type of threat indicator.
            status: Status filter (MALICIOUS, NON_MALICIOUS, SUSPICIOUS, UNKNOWN).
            share_level: Share level filter (RED, AMBER, GREEN, WHITE).
            owner: Owner app ID to filter by.
            tags: List of tags to filter by.
            since: Unix timestamp to filter descriptors updated after this time.
            until: Unix timestamp to filter descriptors updated before this time.
            strict_text: If True, search for exact text match.
            fields: Optional list of fields to include in the response.
            limit: Maximum number of results to return (None for all).

        Yields:
            ThreatDescriptor objects matching the search criteria.
        """
        params: Dict[str, Any] = {}

        if text:
            params["text"] = text
        if type:
            params["type"] = type.value if isinstance(type, DescriptorType) else type
        if status:
            params["status"] = status.value if isinstance(status, Status) else status
        if share_level:
            params["share_level"] = (
                share_level.value if isinstance(share_level, ShareLevel) else share_level
            )
        if owner:
            params["owner"] = owner
        if tags:
            params["tags"] = ",".join(tags)
        if since is not None:
            params["since"] = since
        if until is not None:
            params["until"] = until
        if strict_text:
            params["strict_text"] = "true"
        if fields:
            params["fields"] = ",".join(fields)

        yield from self._paginate(
            "threat_descriptors",
            params,
            ThreatDescriptor.from_dict,
            limit,
        )

    def create_threat_descriptor(
        self,
        indicator: str,
        type: Union[DescriptorType, str],
        description: str,
        share_level: Union[ShareLevel, str] = ShareLevel.AMBER,
        status: Union[Status, str] = Status.UNKNOWN,
        severity: Optional[Union[Severity, str]] = None,
        privacy_type: str = "VISIBLE",
        privacy_members: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        expired_on: Optional[int] = None,
        first_active: Optional[int] = None,
        last_active: Optional[int] = None,
        review_status: Optional[Union[ReviewStatus, str]] = None,
    ) -> str:
        """
        Create a new threat descriptor.

        Args:
            indicator: The threat indicator value (e.g., domain, IP, hash).
            type: Type of threat indicator.
            description: Description of the threat.
            share_level: Sharing level (default: AMBER).
            status: Threat status (default: UNKNOWN).
            severity: Threat severity.
            privacy_type: Privacy type (VISIBLE or HAS_PRIVACY_GROUP).
            privacy_members: List of privacy group IDs if privacy_type is HAS_PRIVACY_GROUP.
            tags: List of tags to apply.
            expired_on: Unix timestamp when the indicator expires.
            first_active: Unix timestamp when the indicator was first seen.
            last_active: Unix timestamp when the indicator was last seen.
            review_status: Review status of the descriptor.

        Returns:
            ID of the created threat descriptor.

        Raises:
            ValidationError: If required parameters are missing or invalid.
        """
        data: Dict[str, Any] = {
            "indicator": indicator,
            "type": type.value if isinstance(type, DescriptorType) else type,
            "description": description,
            "share_level": (
                share_level.value if isinstance(share_level, ShareLevel) else share_level
            ),
            "status": status.value if isinstance(status, Status) else status,
            "privacy_type": privacy_type,
        }

        if severity:
            data["severity"] = severity.value if isinstance(severity, Severity) else severity
        if privacy_members:
            data["privacy_members"] = ",".join(privacy_members)
        if tags:
            data["tags"] = ",".join(tags)
        if expired_on is not None:
            data["expired_on"] = expired_on
        if first_active is not None:
            data["first_active"] = first_active
        if last_active is not None:
            data["last_active"] = last_active
        if review_status:
            data["review_status"] = (
                review_status.value if isinstance(review_status, ReviewStatus) else review_status
            )

        result = self._post("threat_descriptors", data=data)
        return result.get("id", "")

    def update_threat_descriptor(
        self,
        descriptor_id: str,
        description: Optional[str] = None,
        status: Optional[Union[Status, str]] = None,
        severity: Optional[Union[Severity, str]] = None,
        share_level: Optional[Union[ShareLevel, str]] = None,
        privacy_type: Optional[str] = None,
        privacy_members: Optional[List[str]] = None,
        expired_on: Optional[int] = None,
        first_active: Optional[int] = None,
        last_active: Optional[int] = None,
        review_status: Optional[Union[ReviewStatus, str]] = None,
    ) -> bool:
        """
        Update an existing threat descriptor.

        Args:
            descriptor_id: The ID of the descriptor to update.
            description: New description.
            status: New status.
            severity: New severity.
            share_level: New share level.
            privacy_type: New privacy type.
            privacy_members: New privacy members.
            expired_on: New expiration timestamp.
            first_active: New first active timestamp.
            last_active: New last active timestamp.
            review_status: New review status.

        Returns:
            True if the update was successful.
        """
        data: Dict[str, Any] = {}

        if description is not None:
            data["description"] = description
        if status is not None:
            data["status"] = status.value if isinstance(status, Status) else status
        if severity is not None:
            data["severity"] = severity.value if isinstance(severity, Severity) else severity
        if share_level is not None:
            data["share_level"] = (
                share_level.value if isinstance(share_level, ShareLevel) else share_level
            )
        if privacy_type is not None:
            data["privacy_type"] = privacy_type
        if privacy_members is not None:
            data["privacy_members"] = ",".join(privacy_members)
        if expired_on is not None:
            data["expired_on"] = expired_on
        if first_active is not None:
            data["first_active"] = first_active
        if last_active is not None:
            data["last_active"] = last_active
        if review_status is not None:
            data["review_status"] = (
                review_status.value if isinstance(review_status, ReviewStatus) else review_status
            )

        result = self._post(descriptor_id, data=data)
        return result.get("success", False)

    def delete_threat_descriptor(self, descriptor_id: str) -> bool:
        """
        Delete a threat descriptor.

        Args:
            descriptor_id: The ID of the descriptor to delete.

        Returns:
            True if the deletion was successful.
        """
        result = self._delete(descriptor_id)
        return result.get("success", False)

    def add_descriptor_reaction(
        self,
        descriptor_id: str,
        reaction: str,
    ) -> bool:
        """
        Add a reaction to a threat descriptor.

        Args:
            descriptor_id: The ID of the descriptor.
            reaction: The reaction type (e.g., HELPFUL, NOT_HELPFUL, OUTDATED, etc.).

        Returns:
            True if the reaction was added successfully.
        """
        result = self._post(f"{descriptor_id}/reactions", data={"reaction": reaction})
        return result.get("success", False)

    def remove_descriptor_reaction(self, descriptor_id: str) -> bool:
        """
        Remove a reaction from a threat descriptor.

        Args:
            descriptor_id: The ID of the descriptor.

        Returns:
            True if the reaction was removed successfully.
        """
        result = self._delete(f"{descriptor_id}/reactions")
        return result.get("success", False)
