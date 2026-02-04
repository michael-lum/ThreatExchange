"""
Privacy Groups endpoint mixin.

Provides methods for managing privacy groups.
"""

from typing import Any, Dict, Iterator, Optional

from ..models import ThreatPrivacyGroup
from ..exceptions import ValidationError


class PrivacyGroupsMixin:
    """Mixin providing privacy group operations."""

    def get_privacy_group(self, group_id: str) -> ThreatPrivacyGroup:
        """
        Get a specific privacy group by ID.

        Args:
            group_id: The ID of the privacy group.

        Returns:
            ThreatPrivacyGroup object.
        """
        result = self._get(group_id)
        return ThreatPrivacyGroup.from_dict(result)

    def get_my_privacy_groups(
        self,
        limit: Optional[int] = None,
    ) -> Iterator[ThreatPrivacyGroup]:
        """
        Get privacy groups the current app belongs to.

        Args:
            limit: Maximum number of results to return.

        Yields:
            ThreatPrivacyGroup objects.
        """
        if not self.app_id:
            raise ValidationError("app_id is required to get privacy groups")

        yield from self._paginate(
            f"{self.app_id}/threat_exchange_members",
            None,
            ThreatPrivacyGroup.from_dict,
            limit,
        )

    def create_privacy_group(
        self,
        name: str,
        description: str = "",
    ) -> str:
        """
        Create a new privacy group.

        Args:
            name: Name of the privacy group.
            description: Description of the privacy group.

        Returns:
            ID of the created privacy group.
        """
        result = self._post(
            "threat_privacy_groups",
            data={"name": name, "description": description},
        )
        return result.get("id", "")

    def add_privacy_group_member(
        self,
        group_id: str,
        member_id: str,
    ) -> bool:
        """
        Add a member to a privacy group.

        Args:
            group_id: The ID of the privacy group.
            member_id: The app ID of the member to add.

        Returns:
            True if the member was added successfully.
        """
        result = self._post(f"{group_id}/members", data={"member": member_id})
        return result.get("success", False)

    def remove_privacy_group_member(
        self,
        group_id: str,
        member_id: str,
    ) -> bool:
        """
        Remove a member from a privacy group.

        Args:
            group_id: The ID of the privacy group.
            member_id: The app ID of the member to remove.

        Returns:
            True if the member was removed successfully.
        """
        result = self._delete(f"{group_id}/members", params={"member": member_id})
        return result.get("success", False)
