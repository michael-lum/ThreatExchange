#!/usr/bin/env python3
"""
Example: Sync threat updates incrementally.

This example demonstrates how to use the threat_updates endpoint
to efficiently sync changes to threat data since your last sync.
"""

import os
import sys
import time
import json
from pathlib import Path
from typing import Optional

# Add parent directory to path for development
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threatexchange_client import ThreatExchangeClient
from threatexchange_client.exceptions import ThreatExchangeError


# File to store the last sync timestamp
SYNC_STATE_FILE = Path("sync_state.json")


def load_last_sync_time() -> "Optional[int]":
    """Load the last sync timestamp from file."""
    if SYNC_STATE_FILE.exists():
        with open(SYNC_STATE_FILE) as f:
            data = json.load(f)
            return data.get("last_sync")
    return None


def save_last_sync_time(timestamp: int):
    """Save the last sync timestamp to file."""
    with open(SYNC_STATE_FILE, "w") as f:
        json.dump({"last_sync": timestamp}, f)


def main():
    # Get access token from environment variable
    access_token = os.environ.get("THREATEXCHANGE_ACCESS_TOKEN")
    if not access_token:
        print("Error: Set THREATEXCHANGE_ACCESS_TOKEN environment variable")
        sys.exit(1)

    # Get privacy group ID from environment or command line
    privacy_group_id = os.environ.get("THREATEXCHANGE_PRIVACY_GROUP_ID")
    if len(sys.argv) > 1:
        privacy_group_id = sys.argv[1]

    if not privacy_group_id:
        print("Error: Provide privacy group ID as argument or set THREATEXCHANGE_PRIVACY_GROUP_ID")
        print("Usage: python sync_updates.py <privacy_group_id>")
        sys.exit(1)

    client = ThreatExchangeClient(access_token=access_token)

    # Get the last sync time, or default to 1 hour ago for first run
    last_sync = load_last_sync_time()
    if last_sync is None:
        last_sync = int(time.time()) - 3600  # 1 hour ago
        print(f"First sync - fetching updates from the last hour")
    else:
        print(f"Resuming sync from timestamp: {last_sync}")

    print(f"Privacy group: {privacy_group_id}")

    # Track the current time for the next sync
    current_time = int(time.time())

    try:
        print("\nFetching threat updates...")
        print("-" * 60)

        updates_count = 0
        additions = 0
        deletions = 0

        for update in client.get_threat_updates(
            privacy_group_id=privacy_group_id,
            since=last_sync,
            types=["THREAT_DESCRIPTOR"],
            limit=100,  # Limit for this example
        ):
            updates_count += 1

            if update.should_delete:
                deletions += 1
                print(f"DELETE: {update.id} (type: {update.type})")
            else:
                additions += 1
                print(f"ADD/UPDATE: {update.id} (type: {update.type})")

        print("-" * 60)
        print(f"\nSync summary:")
        print(f"  Total updates: {updates_count}")
        print(f"  Additions/Updates: {additions}")
        print(f"  Deletions: {deletions}")

        # Save the sync state for next run
        save_last_sync_time(current_time)
        print(f"\nSaved sync state (timestamp: {current_time})")

    except ThreatExchangeError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
