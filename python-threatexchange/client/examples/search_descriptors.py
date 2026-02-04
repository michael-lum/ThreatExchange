#!/usr/bin/env python3
"""
Example: Search for threat descriptors related to a domain.

This example demonstrates how to search for threat intelligence
data in ThreatExchange.
"""

import os
import sys

# Add parent directory to path for development
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threatexchange_client import (
    ThreatExchangeClient,
    DescriptorType,
    Status,
)


def main():
    # Get access token from environment variable
    access_token = os.environ.get("THREATEXCHANGE_ACCESS_TOKEN")
    if not access_token:
        print("Error: Set THREATEXCHANGE_ACCESS_TOKEN environment variable")
        sys.exit(1)

    # Create client
    client = ThreatExchangeClient(access_token=access_token)

    # Search for malicious domains
    print("Searching for malicious domains containing 'malware'...")
    print("-" * 60)

    count = 0
    for descriptor in client.search_threat_descriptors(
        text="malware",
        type=DescriptorType.DOMAIN,
        status=Status.MALICIOUS,
        limit=10,
    ):
        count += 1
        print(f"\nDescriptor #{count}")
        print(f"  ID: {descriptor.id}")
        print(f"  Indicator: {descriptor.indicator}")
        print(f"  Status: {descriptor.status}")
        print(f"  Severity: {descriptor.severity}")
        print(f"  Description: {descriptor.description}")
        print(f"  Owner: {descriptor.owner_name}")
        print(f"  Tags: {', '.join(descriptor.tags) if descriptor.tags else 'None'}")

    print("-" * 60)
    print(f"Total descriptors found: {count}")


if __name__ == "__main__":
    main()
