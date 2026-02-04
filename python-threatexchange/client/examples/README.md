# Examples

This directory contains example scripts demonstrating how to use the ThreatExchange Python client.

## Prerequisites

1. Set your ThreatExchange access token as an environment variable:

```bash
export THREATEXCHANGE_ACCESS_TOKEN="your_access_token_here"
```

2. Install the client:

```bash
cd ..
pip install -e .
```

## Available Examples

### search_descriptors.py

Search for threat descriptors in ThreatExchange.

```bash
python search_descriptors.py
```

This example:
- Searches for malicious domains containing "malware"
- Displays the first 10 results with details

### create_descriptor.py

Create, update, and delete threat descriptors.

```bash
python create_descriptor.py
```

This example:
- Creates a new threat descriptor
- Updates its status and description
- Adds a reaction
- Deletes the descriptor (cleanup)

**Note:** This example creates real data in ThreatExchange. The descriptor is deleted at the end of the script.

### sync_updates.py

Incrementally sync threat updates for a privacy group.

```bash
python sync_updates.py <privacy_group_id>

# Or set the environment variable
export THREATEXCHANGE_PRIVACY_GROUP_ID="your_group_id"
python sync_updates.py
```

This example:
- Loads the last sync timestamp from a state file
- Fetches all updates since the last sync
- Tracks additions and deletions
- Saves the new sync timestamp for the next run

Run multiple times to see incremental updates.

## Getting an Access Token

1. Go to [developers.facebook.com](https://developers.facebook.com/)
2. Create or select your app
3. Ensure your app has ThreatExchange access (request if needed)
4. Go to Tools > Graph API Explorer
5. Select your app and generate an access token with `threat_exchange` permission
