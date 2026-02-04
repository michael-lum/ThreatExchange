"""
Tests for the ThreatExchange client.
"""

import pytest
import responses

from threatexchange_client import (
    ThreatExchangeClient,
    ThreatDescriptor,
    MalwareAnalysis,
    ThreatTag,
    DescriptorType,
    Status,
    ShareLevel,
    Severity,
)
from threatexchange_client.exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ValidationError,
)


@pytest.fixture
def client():
    """Create a test client."""
    return ThreatExchangeClient(
        access_token="test_token",
        app_id="test_app_id",
        retry_on_rate_limit=False,
    )


@pytest.fixture
def base_url():
    """Get the base API URL."""
    return "https://graph.facebook.com/v19.0"


class TestThreatDescriptors:
    """Tests for threat descriptor operations."""

    @responses.activate
    def test_get_threat_descriptor(self, client, base_url):
        """Test getting a single threat descriptor."""
        responses.add(
            responses.GET,
            f"{base_url}/12345",
            json={
                "id": "12345",
                "indicator": {"indicator": "malware.example.com"},
                "type": "DOMAIN",
                "status": "MALICIOUS",
                "description": "Test descriptor",
                "owner": {"id": "owner123", "name": "Test Owner"},
            },
            status=200,
        )

        descriptor = client.get_threat_descriptor("12345")

        assert descriptor.id == "12345"
        assert descriptor.indicator == "malware.example.com"
        assert descriptor.type == DescriptorType.DOMAIN
        assert descriptor.status == Status.MALICIOUS
        assert descriptor.owner_id == "owner123"

    @responses.activate
    def test_search_threat_descriptors(self, client, base_url):
        """Test searching for threat descriptors."""
        responses.add(
            responses.GET,
            f"{base_url}/threat_descriptors",
            json={
                "data": [
                    {
                        "id": "1",
                        "indicator": {"indicator": "bad1.example.com"},
                        "type": "DOMAIN",
                        "status": "MALICIOUS",
                    },
                    {
                        "id": "2",
                        "indicator": {"indicator": "bad2.example.com"},
                        "type": "DOMAIN",
                        "status": "SUSPICIOUS",
                    },
                ],
                "paging": {},
            },
            status=200,
        )

        descriptors = list(client.search_threat_descriptors(
            text="example",
            type=DescriptorType.DOMAIN,
            limit=10,
        ))

        assert len(descriptors) == 2
        assert descriptors[0].indicator == "bad1.example.com"
        assert descriptors[1].indicator == "bad2.example.com"

    @responses.activate
    def test_create_threat_descriptor(self, client, base_url):
        """Test creating a threat descriptor."""
        responses.add(
            responses.POST,
            f"{base_url}/threat_descriptors",
            json={"id": "new123"},
            status=200,
        )

        descriptor_id = client.create_threat_descriptor(
            indicator="newmalware.example.com",
            type=DescriptorType.DOMAIN,
            description="New malware domain",
            status=Status.MALICIOUS,
            share_level=ShareLevel.AMBER,
        )

        assert descriptor_id == "new123"

    @responses.activate
    def test_update_threat_descriptor(self, client, base_url):
        """Test updating a threat descriptor."""
        responses.add(
            responses.POST,
            f"{base_url}/12345",
            json={"success": True},
            status=200,
        )

        result = client.update_threat_descriptor(
            "12345",
            status=Status.NON_MALICIOUS,
            description="Updated description",
        )

        assert result is True

    @responses.activate
    def test_delete_threat_descriptor(self, client, base_url):
        """Test deleting a threat descriptor."""
        responses.add(
            responses.DELETE,
            f"{base_url}/12345",
            json={"success": True},
            status=200,
        )

        result = client.delete_threat_descriptor("12345")

        assert result is True


class TestMalwareAnalyses:
    """Tests for malware analysis operations."""

    @responses.activate
    def test_get_malware_analysis(self, client, base_url):
        """Test getting a single malware analysis."""
        responses.add(
            responses.GET,
            f"{base_url}/67890",
            json={
                "id": "67890",
                "sha256": "a" * 64,
                "md5": "b" * 32,
                "file_name": "malware.exe",
                "file_type": "PE32",
                "status": "MALICIOUS",
            },
            status=200,
        )

        analysis = client.get_malware_analysis("67890")

        assert analysis.id == "67890"
        assert analysis.sha256 == "a" * 64
        assert analysis.file_name == "malware.exe"
        assert analysis.status == Status.MALICIOUS

    @responses.activate
    def test_search_malware_analyses(self, client, base_url):
        """Test searching for malware analyses."""
        responses.add(
            responses.GET,
            f"{base_url}/malware_analyses",
            json={
                "data": [
                    {"id": "1", "sha256": "a" * 64, "file_name": "sample1.exe"},
                    {"id": "2", "sha256": "b" * 64, "file_name": "sample2.dll"},
                ],
                "paging": {},
            },
            status=200,
        )

        analyses = list(client.search_malware_analyses(text="sample", limit=10))

        assert len(analyses) == 2
        assert analyses[0].file_name == "sample1.exe"


class TestThreatTags:
    """Tests for threat tag operations."""

    @responses.activate
    def test_search_threat_tags(self, client, base_url):
        """Test searching for threat tags."""
        responses.add(
            responses.GET,
            f"{base_url}/threat_tags",
            json={
                "data": [
                    {"id": "tag1", "text": "ransomware", "tagged_objects_count": 100},
                    {"id": "tag2", "text": "ransomware-variant", "tagged_objects_count": 50},
                ],
                "paging": {},
            },
            status=200,
        )

        tags = list(client.search_threat_tags(text="ransomware"))

        assert len(tags) == 2
        assert tags[0].text == "ransomware"
        assert tags[0].tagged_objects_count == 100


class TestErrorHandling:
    """Tests for error handling."""

    @responses.activate
    def test_authentication_error(self, client, base_url):
        """Test authentication error handling."""
        responses.add(
            responses.GET,
            f"{base_url}/12345",
            json={
                "error": {
                    "message": "Invalid OAuth access token.",
                    "type": "OAuthException",
                    "code": 190,
                }
            },
            status=400,
        )

        with pytest.raises(AuthenticationError) as exc_info:
            client.get_threat_descriptor("12345")

        assert "Invalid OAuth access token" in str(exc_info.value)

    @responses.activate
    def test_not_found_error(self, client, base_url):
        """Test not found error handling."""
        responses.add(
            responses.GET,
            f"{base_url}/invalid",
            json={
                "error": {
                    "message": "Object does not exist",
                    "type": "GraphMethodException",
                    "code": 803,
                }
            },
            status=404,
        )

        with pytest.raises(NotFoundError):
            client.get_threat_descriptor("invalid")

    @responses.activate
    def test_rate_limit_error(self, client, base_url):
        """Test rate limit error handling."""
        responses.add(
            responses.GET,
            f"{base_url}/12345",
            json={
                "error": {
                    "message": "Application request limit reached",
                    "type": "OAuthException",
                    "code": 4,
                }
            },
            status=429,
        )

        with pytest.raises(RateLimitError):
            client.get_threat_descriptor("12345")

    @responses.activate
    def test_validation_error(self, client, base_url):
        """Test validation error handling."""
        responses.add(
            responses.POST,
            f"{base_url}/threat_descriptors",
            json={
                "error": {
                    "message": "Invalid parameter",
                    "type": "GraphMethodException",
                    "code": 100,
                }
            },
            status=400,
        )

        with pytest.raises(ValidationError):
            client.create_threat_descriptor(
                indicator="",
                type=DescriptorType.DOMAIN,
                description="Test",
            )


class TestPagination:
    """Tests for pagination handling."""

    @responses.activate
    def test_pagination_multiple_pages(self, client, base_url):
        """Test that pagination correctly fetches multiple pages."""
        # First page
        responses.add(
            responses.GET,
            f"{base_url}/threat_descriptors",
            json={
                "data": [{"id": "1", "indicator": {"indicator": "page1.com"}}],
                "paging": {"next": f"{base_url}/threat_descriptors?after=cursor1"},
            },
            status=200,
        )

        # Second page
        responses.add(
            responses.GET,
            f"{base_url}/threat_descriptors",
            json={
                "data": [{"id": "2", "indicator": {"indicator": "page2.com"}}],
                "paging": {},
            },
            status=200,
        )

        descriptors = list(client.search_threat_descriptors(text="test"))

        assert len(descriptors) == 2
        assert descriptors[0].indicator == "page1.com"
        assert descriptors[1].indicator == "page2.com"


class TestContextManager:
    """Tests for context manager support."""

    def test_context_manager(self):
        """Test that the client works as a context manager."""
        with ThreatExchangeClient(access_token="test") as client:
            assert client.access_token == "test"


class TestModels:
    """Tests for data models."""

    def test_threat_descriptor_from_dict(self):
        """Test creating ThreatDescriptor from dict."""
        data = {
            "id": "123",
            "indicator": {"indicator": "test.com"},
            "type": "DOMAIN",
            "status": "MALICIOUS",
            "severity": "SEVERE",
            "share_level": "AMBER",
            "description": "Test",
            "owner": {"id": "owner1", "name": "Owner Name"},
            "added_on": 1700000000,
            "tags": {"data": [{"text": "tag1"}, {"text": "tag2"}]},
        }

        descriptor = ThreatDescriptor.from_dict(data)

        assert descriptor.id == "123"
        assert descriptor.indicator == "test.com"
        assert descriptor.type == DescriptorType.DOMAIN
        assert descriptor.status == Status.MALICIOUS
        assert descriptor.severity == Severity.SEVERE
        assert descriptor.share_level == ShareLevel.AMBER
        assert descriptor.owner_name == "Owner Name"
        assert descriptor.tags == ["tag1", "tag2"]

    def test_malware_analysis_from_dict(self):
        """Test creating MalwareAnalysis from dict."""
        data = {
            "id": "456",
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "file_name": "test.exe",
            "file_size": 1024,
            "status": "MALICIOUS",
        }

        analysis = MalwareAnalysis.from_dict(data)

        assert analysis.id == "456"
        assert analysis.sha256 == "a" * 64
        assert analysis.file_name == "test.exe"
        assert analysis.file_size == 1024
