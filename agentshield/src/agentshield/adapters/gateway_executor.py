"""Gateway Executor - HTTP client for Protected Tool Gateway.

This adapter allows AgentShield to call protected enterprise services through the gateway,
enforcing the service boundary defined in the architecture.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Callable
import httpx

from ..core.exceptions import ToolExecutionError, GatewayConnectionError


class BaseToolExecutor(ABC):
    """Abstract base class for tool execution strategies."""

    @abstractmethod
    def execute(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        request_id: str,
        validated_params: Optional[Any] = None
    ) -> Any:
        """Execute a tool call."""
        pass


class LocalExecutor(BaseToolExecutor):
    """
    Executes a local Python callable.
    Preserved strictly as a testing adapter; not used in protected production/demo path.
    """

    def __init__(self, callable_fn: Callable):
        self.callable_fn = callable_fn

    def execute(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        request_id: str,
        validated_params: Optional[Any] = None
    ) -> Any:
        if validated_params is not None:
            try:
                return self.callable_fn(validated_params)
            except TypeError:
                return self.callable_fn(parameters)
        return self.callable_fn(parameters)


class GatewayExecutor(BaseToolExecutor):
    """Executes tool calls via the Protected Tool Gateway service boundary."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8001",
        auth_token: Optional[str] = None,
        timeout: float = 30.0,
        client: Optional[Any] = None
    ):
        """
        Initialize the Gateway Executor.

        Args:
            base_url: URL of the Protected Tool Gateway
            auth_token: Internal authentication token (must be kept secret from AI agent)
            timeout: Request timeout in seconds
            client: Optional pre-configured client (e.g. TestClient for tests)
        """
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token or "gateway-secret-token-mvp"
        self.timeout = timeout
        self.client = client

        # Validate that auth token is provided
        if not self.auth_token:
            raise ValueError("Gateway auth token is required")

    def _get_headers(self) -> Dict[str, str]:
        """Get headers with internal authentication."""
        return {
            "X-AgentShield-Auth": self.auth_token,
            "Content-Type": "application/json"
        }

    def _get_client(self):
        """Return a client context manager."""
        if self.client is not None:
            from contextlib import nullcontext
            return nullcontext(self.client)
        return httpx.Client(timeout=self.timeout)

    def execute(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        request_id: str,
        validated_params: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Execute a tool call via the gateway.

        Args:
            tool_name: Name of the tool to execute
            parameters: Tool parameters (already validated by AgentShield)
            request_id: Unique request ID for idempotency
            validated_params: Optional validated model instance (unused by gateway)

        Returns:
            Tool execution result

        Raises:
            GatewayConnectionError: If gateway is unreachable, times out, or auth fails
            ToolExecutionError: If tool execution fails or parameters conflict
        """
        endpoint = self._get_endpoint_for_tool(tool_name)
        url = endpoint if self.client is not None else f"{self.base_url}{endpoint}"

        try:
            with self._get_client() as client:
                response = client.post(
                    url,
                    json=parameters,
                    headers=self._get_headers(),
                    params={"request_id": request_id}
                )

                if response.status_code == 401:
                    raise GatewayConnectionError("Gateway authentication failed: missing token")
                elif response.status_code == 403:
                    raise GatewayConnectionError("Gateway authentication failed: invalid token")
                elif response.status_code == 404:
                    raise ToolExecutionError(f"Gateway endpoint not found for tool: {tool_name}")
                elif response.status_code == 409:
                    error_detail = response.json().get("detail", "Unknown")
                    raise ToolExecutionError(f"Request ID conflict: {error_detail}")
                elif response.status_code >= 500:
                    raise GatewayConnectionError(
                        f"Gateway server error: {response.status_code}"
                    )
                elif response.status_code >= 400:
                    error_detail = response.json().get("detail", "Unknown error")
                    raise ToolExecutionError(f"Gateway rejected request: {error_detail}")

                result = response.json()

                if not result.get("success"):
                    raise ToolExecutionError(result.get("error", "Tool execution failed"))

                return result.get("result", {})

        except (httpx.ConnectError, ConnectionRefusedError) as e:
            raise GatewayConnectionError(f"Cannot connect to gateway at {url}: {e}")
        except httpx.TimeoutException as e:
            raise GatewayConnectionError(f"Gateway request timed out: {e}")
        except httpx.HTTPError as e:
            raise GatewayConnectionError(f"Gateway HTTP error: {e}")

    def _get_endpoint_for_tool(self, tool_name: str) -> str:
        """Map tool name to gateway endpoint."""
        endpoints = {
            "transfer_money": "/tools/transfer_money",
            "send_email": "/tools/send_email",
            "get_customer": "/tools/customer",
            "search_customers": "/tools/search_customers",
            "export_customer_data": "/tools/export_customers",
        }

        if tool_name not in endpoints:
            raise ToolExecutionError(f"Unknown tool: {tool_name}")

        return endpoints[tool_name]

    def health_check(self) -> bool:
        """Check if gateway is healthy."""
        url = "/health" if self.client is not None else f"{self.base_url}/health"
        try:
            with self._get_client() as client:
                response = client.get(
                    url,
                    headers=self._get_headers()
                )
                if response.status_code == 200:
                    return True
                # Fallback to POST for compatibility
                response = client.post(
                    url,
                    headers=self._get_headers()
                )
                return response.status_code == 200
        except Exception:
            return False

    def reset_services(self) -> Dict[str, Any]:
        """Reset all mock services (for testing)."""
        url = "/admin/reset" if self.client is not None else f"{self.base_url}/admin/reset"
        try:
            with self._get_client() as client:
                response = client.post(
                    url,
                    headers=self._get_headers()
                )
                result = response.json()
                if not result.get("success"):
                    raise ToolExecutionError(result.get("error", "Reset failed"))
                return result.get("result", {})
        except Exception as e:
            raise ToolExecutionError(f"Failed to reset services: {e}")
