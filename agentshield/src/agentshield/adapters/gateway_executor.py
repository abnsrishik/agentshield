"""Gateway Executor - HTTP client for Protected Tool Gateway.

This adapter allows AgentShield to call protected enterprise services through the gateway,
enforcing the service boundary defined in the architecture.
"""

import httpx
from typing import Dict, Any, Optional
from datetime import timedelta

from ..core.exceptions import ToolExecutionError, GatewayConnectionError


class GatewayExecutor:
    """Executes tool calls via the Protected Tool Gateway."""
    
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8001",
        auth_token: Optional[str] = None,
        timeout: float = 30.0
    ):
        """
        Initialize the Gateway Executor.
        
        Args:
            base_url: URL of the Protected Tool Gateway
            auth_token: Internal authentication token (must be kept secret from AI agent)
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token or "gateway-secret-token-mvp"
        self.timeout = timeout
        
        # Validate that auth token is provided
        if not self.auth_token:
            raise ValueError("Gateway auth token is required")
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers with internal authentication."""
        return {
            "X-AgentShield-Auth": self.auth_token,
            "Content-Type": "application/json"
        }
    
    def execute(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        request_id: str
    ) -> Dict[str, Any]:
        """
        Execute a tool call via the gateway.
        
        Args:
            tool_name: Name of the tool to execute
            parameters: Tool parameters (already validated by AgentShield)
            request_id: Unique request ID for idempotency
        
        Returns:
            Tool execution result
        
        Raises:
            GatewayConnectionError: If gateway is unreachable
            ToolExecutionError: If tool execution fails
        """
        endpoint = self._get_endpoint_for_tool(tool_name)
        url = f"{self.base_url}{endpoint}"
        
        try:
            with httpx.Client(timeout=self.timeout) as client:
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
                elif response.status_code == 409:
                    raise ToolExecutionError(
                        f"Request ID conflict: {response.json().get('detail', 'Unknown')}"
                    )
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
                
        except httpx.ConnectError as e:
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
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.post(
                    f"{self.base_url}/health",
                    headers=self._get_headers()
                )
                return response.status_code == 200
        except Exception:
            return False
    
    def reset_services(self) -> Dict[str, Any]:
        """Reset all mock services (for testing)."""
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    f"{self.base_url}/admin/reset",
                    headers=self._get_headers()
                )
                result = response.json()
                if not result.get("success"):
                    raise ToolExecutionError(result.get("error", "Reset failed"))
                return result.get("result", {})
        except Exception as e:
            raise ToolExecutionError(f"Failed to reset services: {e}")
