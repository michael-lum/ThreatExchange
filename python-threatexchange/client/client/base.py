"""
Base HTTP client for ThreatExchange API.

This module provides the low-level HTTP functionality that all endpoint
modules build upon.
"""

import time
from typing import Any, Callable, Dict, Iterator, Optional
from urllib.parse import urljoin, urlparse, parse_qs

import requests

from .exceptions import (
    AuthenticationError,
    NotFoundError,
    PermissionError,
    RateLimitError,
    ThreatExchangeError,
    ValidationError,
)
from .models import PaginatedResponse


class BaseClient:
    """
    Base HTTP client for the ThreatExchange API.

    This class handles all low-level HTTP operations including:
    - Request/response handling
    - Authentication
    - Error handling
    - Rate limit retries
    - Pagination

    Endpoint-specific functionality is provided by mixin classes.
    """

    BASE_URL = "https://graph.facebook.com"
    DEFAULT_VERSION = "v19.0"
    DEFAULT_TIMEOUT = 30
    DEFAULT_LIMIT = 500

    def __init__(
        self,
        access_token: str,
        app_id: Optional[str] = None,
        app_secret: Optional[str] = None,
        version: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        retry_on_rate_limit: bool = True,
        max_retries: int = 3,
    ):
        """
        Initialize the base client.

        Args:
            access_token: Facebook Graph API access token with ThreatExchange permissions.
            app_id: Optional Facebook App ID (used for some operations).
            app_secret: Optional Facebook App Secret (used for some operations).
            version: Graph API version to use (default: v19.0).
            timeout: Request timeout in seconds (default: 30).
            retry_on_rate_limit: Whether to automatically retry on rate limit errors.
            max_retries: Maximum number of retries for rate-limited requests.
        """
        self.access_token = access_token
        self.app_id = app_id
        self.app_secret = app_secret
        self.version = version or self.DEFAULT_VERSION
        self.timeout = timeout
        self.retry_on_rate_limit = retry_on_rate_limit
        self.max_retries = max_retries
        self._session = requests.Session()

    @property
    def _base_url(self) -> str:
        """Get the base API URL."""
        return f"{self.BASE_URL}/{self.version}"

    def _build_url(self, endpoint: str) -> str:
        """Build full API URL for an endpoint."""
        if endpoint.startswith("http"):
            return endpoint
        return urljoin(f"{self._base_url}/", endpoint.lstrip("/"))

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        retry_count: int = 0,
    ) -> Dict[str, Any]:
        """
        Make an API request.

        Args:
            method: HTTP method (GET, POST, DELETE).
            endpoint: API endpoint.
            params: Query parameters.
            data: POST data.
            retry_count: Current retry attempt.

        Returns:
            JSON response from the API.

        Raises:
            ThreatExchangeError: On API errors.
        """
        url = self._build_url(endpoint)
        params = params or {}
        params["access_token"] = self.access_token

        try:
            response = self._session.request(
                method=method,
                url=url,
                params=params if method == "GET" else None,
                data={**params, **(data or {})} if method != "GET" else None,
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise ThreatExchangeError(f"Request failed: {e}") from e

        return self._handle_response(response, method, endpoint, params, data, retry_count)

    def _handle_response(
        self,
        response: requests.Response,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]],
        data: Optional[Dict[str, Any]],
        retry_count: int,
    ) -> Dict[str, Any]:
        """Handle API response and errors."""
        try:
            result = response.json()
        except ValueError:
            if response.status_code >= 400:
                raise ThreatExchangeError(
                    f"API error: {response.status_code} - {response.text}",
                    code=response.status_code,
                )
            raise ThreatExchangeError("Invalid JSON response from API")

        if "error" in result:
            error = result["error"]
            error_code = error.get("code", 0)
            error_message = error.get("message", "Unknown error")

            # Handle rate limiting
            if error_code in (4, 17, 613) or "rate limit" in error_message.lower():
                if self.retry_on_rate_limit and retry_count < self.max_retries:
                    retry_after = self._get_retry_after(response)
                    time.sleep(retry_after)
                    return self._request(method, endpoint, params, data, retry_count + 1)
                raise RateLimitError(
                    error_message,
                    code=error_code,
                    retry_after=self._get_retry_after(response),
                )

            # Handle authentication errors
            if error_code in (190, 102, 463, 467):
                raise AuthenticationError(error_message, code=error_code)

            # Handle not found
            if error_code == 803 or response.status_code == 404:
                raise NotFoundError(error_message, code=error_code)

            # Handle permission errors
            if error_code in (10, 200, 294):
                raise PermissionError(error_message, code=error_code)

            # Handle validation errors
            if error_code == 100:
                raise ValidationError(error_message, code=error_code)

            raise ThreatExchangeError(error_message, code=error_code, details=error)

        return result

    def _get_retry_after(self, response: requests.Response) -> int:
        """Get retry-after time from response headers."""
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return int(retry_after)
            except ValueError:
                pass
        return 60  # Default to 60 seconds

    def _get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a GET request."""
        return self._request("GET", endpoint, params=params)

    def _post(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Make a POST request."""
        return self._request("POST", endpoint, params=params, data=data)

    def _delete(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a DELETE request."""
        return self._request("DELETE", endpoint, params=params)

    def _paginate(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        item_factory: Optional[Callable] = None,
        limit: Optional[int] = None,
    ) -> Iterator[Any]:
        """
        Iterate through paginated results.

        Args:
            endpoint: API endpoint.
            params: Query parameters.
            item_factory: Factory function to convert items.
            limit: Maximum number of items to return (None for all).

        Yields:
            Items from the API response.
        """
        params = params or {}
        if "limit" not in params:
            params["limit"] = self.DEFAULT_LIMIT

        count = 0
        next_url = None

        while True:
            if next_url:
                # Parse the next URL to extract params
                parsed = urlparse(next_url)
                query_params = parse_qs(parsed.query)
                # Flatten single-value lists
                params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}
                params["access_token"] = self.access_token
                result = self._get(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", params)
            else:
                result = self._get(endpoint, params)

            response = PaginatedResponse.from_dict(result, item_factory)

            for item in response.data:
                yield item
                count += 1
                if limit and count >= limit:
                    return

            if not response.has_next:
                break

            next_url = response.next_url

    def _upload_file(
        self,
        endpoint: str,
        file_path: Optional[str] = None,
        file_content: Optional[bytes] = None,
        file_name: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Upload a file to an endpoint.

        Args:
            endpoint: API endpoint.
            file_path: Path to the file to upload.
            file_content: File content as bytes.
            file_name: Name of the file.
            data: Additional form data.

        Returns:
            JSON response from the API.
        """
        data = data or {}
        data["access_token"] = self.access_token

        if file_path:
            with open(file_path, "rb") as f:
                files = {"file": (file_name or file_path.split("/")[-1], f)}
                response = self._session.post(
                    self._build_url(endpoint),
                    data=data,
                    files=files,
                    timeout=self.timeout,
                )
        else:
            files = {"file": (file_name, file_content)}
            response = self._session.post(
                self._build_url(endpoint),
                data=data,
                files=files,
                timeout=self.timeout,
            )

        return self._handle_response(response, "POST", endpoint, None, data, 0)

    def close(self) -> None:
        """Close the HTTP session."""
        self._session.close()

    def __enter__(self) -> "BaseClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
