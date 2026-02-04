# ThreatExchange Python Client

A Python client library for interacting with the [Facebook ThreatExchange API](https://developers.facebook.com/docs/threat-exchange/reference/apis).

ThreatExchange is a platform for sharing threat intelligence data with trusted partners to help fight digital harms.

## Installation

```bash
pip install -e .
```

Or install with dependencies:

```bash
pip install requests
```

## Quick Start

### Authentication

You need a Facebook access token with ThreatExchange permissions. To get one:

1. Create a Facebook App at [developers.facebook.com](https://developers.facebook.com/)
2. Request access to ThreatExchange at [developers.facebook.com/products/threat-exchange](https://developers.facebook.com/products/threat-exchange)
3. Generate an access token with the required permissions

```python
from threatexchange_client import ThreatExchangeClient

# Initialize the client
client = ThreatExchangeClient(
    access_token="your_access_token_here"
)
```

### Search for Threat Descriptors

```python
from threatexchange_client import ThreatExchangeClient, IndicatorType, Status

client = ThreatExchangeClient(access_token="your_token")

# Search for malicious domains
for descriptor in client.search_threat_descriptors(
    text="malware",
    type=IndicatorType.DOMAIN,
    status=Status.MALICIOUS,
    limit=10
):
    print(f"Indicator: {descriptor.indicator}")
    print(f"Status: {descriptor.status}")
    print(f"Description: {descriptor.description}")
    print("---")
```

### Create a Threat Descriptor

```python
from threatexchange_client import (
    ThreatExchangeClient,
    IndicatorType,
    Status,
    ShareLevel,
    Severity,
)

client = ThreatExchangeClient(access_token="your_token")

# Share a malicious domain
descriptor_id = client.create_threat_descriptor(
    indicator="malware.example.com",
    type=IndicatorType.DOMAIN,
    description="Known malware distribution domain",
    status=Status.MALICIOUS,
    severity=Severity.SEVERE,
    share_level=ShareLevel.AMBER,
    tags=["malware", "distribution"],
)

print(f"Created descriptor: {descriptor_id}")
```

### Search for Threat Indicators

```python
# Search for indicators
for indicator in client.search_threat_indicators(
    text="example.com",
    type=IndicatorType.DOMAIN,
    limit=10
):
    print(f"Indicator: {indicator.indicator}")
    print(f"Type: {indicator.type}")
```

### Work with Tags

```python
# Search for tags
for tag in client.search_threat_tags(text="ransomware"):
    print(f"Tag: {tag.text} (ID: {tag.id})")

# Get objects with a specific tag
for descriptor in client.get_tagged_objects(tag_id="12345"):
    print(f"Tagged: {descriptor.indicator}")
```

### Get Threat Updates (Incremental Sync)

```python
import time

# Get updates from the last hour for a specific privacy group
one_hour_ago = int(time.time()) - 3600

for update in client.get_threat_updates(
    privacy_group_id="your_privacy_group_id",
    since=one_hour_ago,
    limit=100
):
    print(f"Update ID: {update.id}")
    print(f"Type: {update.type}")
    print(f"Should delete: {update.should_delete}")
```

### Privacy Groups

```python
# Initialize with app_id for privacy group operations
client = ThreatExchangeClient(
    access_token="your_token",
    app_id="your_app_id"
)

# Create a privacy group
group_id = client.create_privacy_group(
    name="My Security Team",
    description="Private threat sharing group"
)

# Add a member
client.add_privacy_group_member(group_id, member_id="partner_app_id")

# List your privacy groups
for group in client.get_my_privacy_groups():
    print(f"Group: {group.name} (ID: {group.id})")
```

### List ThreatExchange Members

```python
# Get all ThreatExchange members
for member in client.get_threat_exchange_members():
    print(f"Member: {member.name} (ID: {member.id})")
```

## Project Structure

The client uses a modular structure that makes it easy to add new endpoints:

```
threatexchange_client/
├── __init__.py          # Package exports
├── client.py            # Main ThreatExchangeClient (combines all mixins)
├── base.py              # Base HTTP client (request handling, pagination)
├── models.py            # Data models (ThreatDescriptor, ThreatIndicator, etc.)
├── exceptions.py        # Custom exceptions
└── endpoints/           # Endpoint-specific code
    ├── __init__.py
    ├── threat_descriptors.py
    ├── threat_indicators.py
    ├── threat_tags.py
    ├── threat_updates.py
    ├── privacy_groups.py
    └── threat_exchange_members.py
```

### Adding New Endpoints

1. Create a new file in `endpoints/` (e.g., `new_endpoint.py`)
2. Define a mixin class with methods using `self._get`, `self._post`, `self._delete`, `self._paginate`
3. Add the mixin to `endpoints/__init__.py`
4. Add the mixin to `ThreatExchangeClient` in `client.py`

Example mixin:
```python
# endpoints/new_endpoint.py
class NewEndpointMixin:
    def get_new_thing(self, thing_id: str):
        result = self._get(f"new_things/{thing_id}")
        return NewThing.from_dict(result)

    def search_new_things(self, text: str, limit: int = None):
        yield from self._paginate(
            "new_things",
            {"text": text},
            NewThing.from_dict,
            limit,
        )
```

## API Reference

### ThreatExchangeClient

The main client class for interacting with the ThreatExchange API.

#### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `access_token` | `str` | Required | Facebook Graph API access token |
| `app_id` | `str` | `None` | Facebook App ID (needed for some operations) |
| `app_secret` | `str` | `None` | Facebook App Secret |
| `version` | `str` | `"v19.0"` | Graph API version |
| `timeout` | `int` | `30` | Request timeout in seconds |
| `retry_on_rate_limit` | `bool` | `True` | Auto-retry on rate limit errors |
| `max_retries` | `int` | `3` | Max retry attempts |

### Endpoints

#### Threat Descriptors

| Method | Description |
|--------|-------------|
| `get_threat_descriptor(id)` | Get a specific descriptor by ID |
| `search_threat_descriptors(...)` | Search for descriptors |
| `create_threat_descriptor(...)` | Create a new descriptor |
| `update_threat_descriptor(id, ...)` | Update an existing descriptor |
| `delete_threat_descriptor(id)` | Delete a descriptor |
| `add_descriptor_reaction(id, reaction)` | Add a reaction |
| `remove_descriptor_reaction(id)` | Remove a reaction |

#### Threat Indicators

| Method | Description |
|--------|-------------|
| `get_threat_indicator(id)` | Get a specific indicator by ID |
| `search_threat_indicators(...)` | Search for indicators |
| `get_indicator_descriptors(id)` | Get descriptors for an indicator |

#### Tags

| Method | Description |
|--------|-------------|
| `get_threat_tag(id)` | Get a specific tag by ID |
| `search_threat_tags(text)` | Search for tags |
| `get_tagged_objects(tag_id)` | Get objects with a tag |

#### Updates

| Method | Description |
|--------|-------------|
| `get_threat_updates(privacy_group_id, ...)` | Get incremental updates for a privacy group |

#### Privacy Groups

| Method | Description |
|--------|-------------|
| `get_privacy_group(id)` | Get a specific group |
| `get_my_privacy_groups()` | List your privacy groups |
| `create_privacy_group(name, description)` | Create a new group |
| `add_privacy_group_member(group_id, member_id)` | Add a member |
| `remove_privacy_group_member(group_id, member_id)` | Remove a member |

#### Members

| Method | Description |
|--------|-------------|
| `get_threat_exchange_members()` | List all ThreatExchange members |
| `get_member(id)` | Get a specific member |

## Data Models

### IndicatorType

Enum of indicator types: `DOMAIN`, `IP_ADDRESS`, `URI`, `EMAIL_ADDRESS`, `HASH_MD5`, `HASH_SHA1`, `HASH_SHA256`, etc.

### Status

Threat status values:
- `MALICIOUS` - Confirmed malicious
- `SUSPICIOUS` - Suspected malicious
- `NON_MALICIOUS` - Confirmed benign
- `UNKNOWN` - Unknown status

### Severity

Threat severity levels:
- `INFO` - Informational
- `WARNING` - Warning level
- `SEVERE` - High severity

### ShareLevel

Traffic Light Protocol (TLP) sharing levels:
- `WHITE` - Unlimited sharing
- `GREEN` - Community sharing
- `AMBER` - Limited sharing
- `RED` - Most restricted

## Error Handling

```python
from threatexchange_client import (
    ThreatExchangeClient,
    ThreatExchangeError,
    AuthenticationError,
    RateLimitError,
    NotFoundError,
    ValidationError,
)

client = ThreatExchangeClient(access_token="your_token")

try:
    descriptor = client.get_threat_descriptor("invalid_id")
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
except NotFoundError as e:
    print(f"Descriptor not found: {e}")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after} seconds")
except ValidationError as e:
    print(f"Invalid parameters: {e}")
except ThreatExchangeError as e:
    print(f"API error [{e.code}]: {e.message}")
```

## Context Manager Support

The client can be used as a context manager to ensure proper cleanup:

```python
with ThreatExchangeClient(access_token="your_token") as client:
    for descriptor in client.search_threat_descriptors(text="malware"):
        print(descriptor.indicator)
# Connection is automatically closed
```

## Pagination

All search methods return iterators that handle pagination automatically:

```python
# Get all results (may make multiple API calls)
for descriptor in client.search_threat_descriptors(text="phishing"):
    process(descriptor)

# Limit results
for descriptor in client.search_threat_descriptors(text="phishing", limit=100):
    process(descriptor)
```

## Rate Limiting

The client automatically handles rate limiting by default:

- When a rate limit error is received, the client waits and retries
- Maximum of 3 retries by default
- Disable with `retry_on_rate_limit=False`

## Resources

- [ThreatExchange Documentation](https://developers.facebook.com/docs/threat-exchange)
- [ThreatExchange API Reference](https://developers.facebook.com/docs/threat-exchange/reference/apis)
- [ThreatExchange GitHub](https://github.com/facebook/ThreatExchange)
