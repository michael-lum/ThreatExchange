"""
Endpoint mixins for the ThreatExchange client.

Each mixin provides methods for a specific API category:
- ThreatDescriptorsMixin: Threat descriptor operations (opinions on indicators)
- ThreatIndicatorsMixin: Threat indicator operations (indicators of compromise)
- ThreatTagsMixin: Threat tag operations (labels for grouping)
- ThreatUpdatesMixin: Threat updates operations (incremental sync)
- PrivacyGroupsMixin: Privacy group operations (sharing controls)
- ThreatExchangeMembersMixin: Member operations (participant info)

To add a new endpoint category:
1. Create a new file in this directory (e.g., `new_category.py`)
2. Define a mixin class with methods that use self._get, self._post, etc.
3. Add the mixin to this __init__.py
4. Add the mixin to ThreatExchangeClient in client.py
"""

from .threat_descriptors import ThreatDescriptorsMixin
from .threat_indicators import ThreatIndicatorsMixin
from .threat_tags import ThreatTagsMixin
from .threat_updates import ThreatUpdatesMixin
from .privacy_groups import PrivacyGroupsMixin
from .threat_exchange_members import ThreatExchangeMembersMixin

__all__ = [
    "ThreatDescriptorsMixin",
    "ThreatIndicatorsMixin",
    "ThreatTagsMixin",
    "ThreatUpdatesMixin",
    "PrivacyGroupsMixin",
    "ThreatExchangeMembersMixin",
]
