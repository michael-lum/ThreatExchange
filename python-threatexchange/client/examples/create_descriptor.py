#!/usr/bin/env python3
"""
Example: Create and manage threat descriptors.

This example demonstrates how to create, update, and delete
threat descriptors in ThreatExchange.
"""

import os
import sys

# Add parent directory to path for development
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threatexchange_client import (
    ThreatExchangeClient,
    DescriptorType,
    Status,
    Severity,
    ShareLevel,
)
from threatexchange_client.exceptions import ThreatExchangeError


def main():
    # Get access token from environment variable
    access_token = os.environ.get("THREATEXCHANGE_ACCESS_TOKEN")
    if not access_token:
        print("Error: Set THREATEXCHANGE_ACCESS_TOKEN environment variable")
        sys.exit(1)

    client = ThreatExchangeClient(access_token=access_token)

    try:
        # Create a new threat descriptor
        print("Creating a new threat descriptor...")

        descriptor_id = client.create_threat_descriptor(
            indicator="example-malware-domain.com",
            type=DescriptorType.DOMAIN,
            description="Example malware distribution domain for testing",
            status=Status.SUSPICIOUS,
            severity=Severity.WARNING,
            share_level=ShareLevel.AMBER,
            tags=["example", "test"],
        )

        print(f"Created descriptor with ID: {descriptor_id}")

        # Get the descriptor we just created
        print("\nFetching the created descriptor...")
        descriptor = client.get_threat_descriptor(descriptor_id)
        print(f"  Indicator: {descriptor.indicator}")
        print(f"  Status: {descriptor.status}")
        print(f"  Description: {descriptor.description}")

        # Update the descriptor
        print("\nUpdating the descriptor status to MALICIOUS...")
        success = client.update_threat_descriptor(
            descriptor_id,
            status=Status.MALICIOUS,
            severity=Severity.SEVERE,
            description="Updated: Confirmed malware distribution domain",
        )
        print(f"Update successful: {success}")

        # Add a reaction
        print("\nAdding a HELPFUL reaction...")
        client.add_descriptor_reaction(descriptor_id, "HELPFUL")
        print("Reaction added")

        # Clean up: Delete the descriptor
        print("\nDeleting the test descriptor...")
        success = client.delete_threat_descriptor(descriptor_id)
        print(f"Delete successful: {success}")

    except ThreatExchangeError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
